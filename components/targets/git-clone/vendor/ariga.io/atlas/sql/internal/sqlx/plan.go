// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package sqlx

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"sort"

	"ariga.io/atlas/sql/migrate"
	"ariga.io/atlas/sql/schema"
)

type (
	execPlanner interface {
		ExecContext(context.Context, string, ...any) (sql.Result, error)
		PlanChanges(context.Context, string, []schema.Change, ...migrate.PlanOption) (*migrate.Plan, error)
	}
	// ApplyError is an error that exposes an information for getting
	// how any changes were applied before encountering the failure.
	ApplyError struct {
		err     string
		applied int
	}
)

// Applied reports how many changes were applied before getting an error.
// In case the first change was failed, Applied() returns 0.
func (e *ApplyError) Applied() int {
	return e.applied
}

// Error implements the error interface.
func (e *ApplyError) Error() string {
	return e.err
}

// ApplyChanges is a helper used by the different drivers to apply changes.
func ApplyChanges(ctx context.Context, changes []schema.Change, p execPlanner, opts ...migrate.PlanOption) error {
	plan, err := p.PlanChanges(ctx, "apply", changes, opts...)
	if err != nil {
		return err
	}
	for i, c := range plan.Changes {
		if _, err := p.ExecContext(ctx, c.Cmd, c.Args...); err != nil {
			if c.Comment != "" {
				err = fmt.Errorf("%s: %w", c.Comment, err)
			}
			return &ApplyError{err: err.Error(), applied: i}
		}
	}
	return nil
}

// noRows implements the schema.ExecQuerier for migrate.Driver's without connections.
// This can be useful to always return no rows for queries, and block any execution.
type noRows struct{}

// QueryContext implements the sqlx.ExecQuerier interface.
func (*noRows) QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error) {
	return nil, sql.ErrNoRows
}

// ExecContext implements the sqlx.ExecQuerier interface.
func (*noRows) ExecContext(context.Context, string, ...interface{}) (sql.Result, error) {
	return nil, errors.New("cannot execute statements without a database connection. use Open to create a new Driver")
}

// NoRows to be used by differs and planners without a connection.
var NoRows schema.ExecQuerier = (*noRows)(nil)

// SetReversible sets the Reversible field to
// true if all planned changes are reversible.
func SetReversible(p *migrate.Plan) error {
	reversible := true
	for _, c := range p.Changes {
		stmts, err := c.ReverseStmts()
		if err != nil {
			return err
		}
		if len(stmts) == 0 {
			reversible = false
		}
	}
	p.Reversible = reversible
	return nil
}

// DetachCycles takes a list of schema changes, and detaches
// references between changes if there is at least one circular
// reference in the changeset. More explicitly, it postpones fks
// creation, or deletes fks before deletes their tables.
func DetachCycles(changes []schema.Change) ([]schema.Change, error) {
	sorted, err := sortMap(changes)
	if errors.Is(err, errCycle) {
		return detachReferences(changes), nil
	}
	if err != nil {
		return nil, err
	}
	planned := make([]schema.Change, len(changes))
	copy(planned, changes)
	sort.Slice(planned, func(i, j int) bool {
		return sorted[table(planned[i])] < sorted[table(planned[j])]
	})
	return planned, nil
}

// detachReferences detaches all table references.
func detachReferences(changes []schema.Change) []schema.Change {
	var planned, deferred []schema.Change
	for _, change := range changes {
		switch change := change.(type) {
		case *schema.AddTable:
			var (
				ext  []schema.Change
				self []*schema.ForeignKey
			)
			for _, fk := range change.T.ForeignKeys {
				if fk.RefTable == change.T {
					self = append(self, fk)
				} else {
					ext = append(ext, &schema.AddForeignKey{F: fk})
				}
			}
			if len(ext) > 0 {
				deferred = append(deferred, &schema.ModifyTable{T: change.T, Changes: ext})
				t := *change.T
				t.ForeignKeys = self
				change = &schema.AddTable{T: &t, Extra: change.Extra}
			}
			planned = append(planned, change)
		case *schema.DropTable:
			var fks []schema.Change
			for _, fk := range change.T.ForeignKeys {
				if fk.RefTable != change.T {
					fks = append(fks, &schema.DropForeignKey{F: fk})
				}
			}
			if len(fks) > 0 {
				planned = append(planned, &schema.ModifyTable{T: change.T, Changes: fks})
				t := *change.T
				t.ForeignKeys = nil
				change = &schema.DropTable{T: &t, Extra: change.Extra}
			}
			deferred = append(deferred, change)
		case *schema.ModifyTable:
			var fks, rest []schema.Change
			for _, c := range change.Changes {
				switch c := c.(type) {
				case *schema.AddForeignKey:
					fks = append(fks, c)
				default:
					rest = append(rest, c)
				}
			}
			if len(fks) > 0 {
				deferred = append(deferred, &schema.ModifyTable{T: change.T, Changes: fks})
			}
			if len(rest) > 0 {
				planned = append(planned, &schema.ModifyTable{T: change.T, Changes: rest})
			}
		default:
			planned = append(planned, change)
		}
	}
	return append(planned, deferred...)
}

// errCycle is an internal error to indicate a case of a cycle.
var errCycle = errors.New("cycle detected")

// sortMap returns an index-map indicates the position of table in a topological
// sort in reversed order based on its references, and a boolean indicate if there
// is a non-self loop.
func sortMap(changes []schema.Change) (map[string]int, error) {
	var (
		visit     func(string) bool
		sorted    = make(map[string]int)
		progress  = make(map[string]bool)
		deps, err = dependencies(changes)
	)
	if err != nil {
		return nil, err
	}
	visit = func(name string) bool {
		if _, done := sorted[name]; done {
			return false
		}
		if progress[name] {
			return true
		}
		progress[name] = true
		for _, ref := range deps[name] {
			if visit(ref.Name) {
				return true
			}
		}
		delete(progress, name)
		sorted[name] = len(sorted)
		return false
	}
	for _, node := range byKeys(deps) {
		if visit(node.K) {
			return nil, errCycle
		}
	}
	return sorted, nil
}

// dependencies returned an adjacency list of all tables and the tables they depend on.
func dependencies(changes []schema.Change) (map[string][]*schema.Table, error) {
	deps := make(map[string][]*schema.Table)
	for _, change := range changes {
		switch change := change.(type) {
		case *schema.AddTable:
			for _, fk := range change.T.ForeignKeys {
				if err := checkFK(fk); err != nil {
					return nil, err
				}
				if fk.RefTable != change.T {
					deps[change.T.Name] = append(deps[change.T.Name], fk.RefTable)
				}
			}
		case *schema.DropTable:
			for _, fk := range change.T.ForeignKeys {
				if err := checkFK(fk); err != nil {
					return nil, err
				}
				if isDropped(changes, fk.RefTable) {
					deps[fk.RefTable.Name] = append(deps[fk.RefTable.Name], fk.Table)
				}
			}
		case *schema.ModifyTable:
			for _, c := range change.Changes {
				switch c := c.(type) {
				case *schema.AddForeignKey:
					if err := checkFK(c.F); err != nil {
						return nil, err
					}
					if c.F.RefTable != change.T {
						deps[change.T.Name] = append(deps[change.T.Name], c.F.RefTable)
					}
				case *schema.ModifyForeignKey:
					if err := checkFK(c.To); err != nil {
						return nil, err
					}
					if c.To.RefTable != change.T {
						deps[change.T.Name] = append(deps[change.T.Name], c.To.RefTable)
					}
				case *schema.DropForeignKey:
					if err := checkFK(c.F); err != nil {
						return nil, err
					}
					if isDropped(changes, c.F.RefTable) {
						deps[c.F.RefTable.Name] = append(deps[c.F.RefTable.Name], c.F.Table)
					}
				}
			}
		}
	}
	return deps, nil
}

func checkFK(fk *schema.ForeignKey) error {
	var cause []string
	if fk.Table == nil {
		cause = append(cause, "child table")
	}
	if len(fk.Columns) == 0 {
		cause = append(cause, "child columns")
	}
	if fk.RefTable == nil {
		cause = append(cause, "parent table")
	}
	if len(fk.RefColumns) == 0 {
		cause = append(cause, "parent columns")
	}
	if len(cause) != 0 {
		return fmt.Errorf("missing %q for foreign key: %q", cause, fk.Symbol)
	}
	return nil
}

// table extracts a table from the given change.
func table(change schema.Change) (t string) {
	switch change := change.(type) {
	case *schema.AddTable:
		t = change.T.Name
	case *schema.DropTable:
		t = change.T.Name
	case *schema.ModifyTable:
		t = change.T.Name
	}
	return
}

// isDropped checks if the given table is marked as a deleted in the changeset.
func isDropped(changes []schema.Change, t *schema.Table) bool {
	for _, c := range changes {
		if c, ok := c.(*schema.DropTable); ok && c.T.Name == t.Name {
			return true
		}
	}
	return false
}

// CheckChangesScope checks that changes can be applied
// on a schema scope (connection).
func CheckChangesScope(opts migrate.PlanOptions, changes []schema.Change) error {
	names := make(map[string]struct{})
	for _, c := range changes {
		var t *schema.Table
		switch c := c.(type) {
		case *schema.ModifySchema:
			switch scope := V(opts.SchemaQualifier); {
			case !opts.Mode.Is(migrate.PlanModeInPlace):
				// The migration plan is generated for deferred execution.
				return fmt.Errorf("%T is not allowed when migration plan is scoped to one schema", c)
			case scope != "" && scope != c.S.Name:
				// Other schemas can not be modified when the migration plan is scoped to one schema.
				return fmt.Errorf("modify schema %s is not allowed when migration plan is scoped to schema %s", c.S.Name, scope)
			default:
				names[c.S.Name] = struct{}{}
				continue
			}
		case *schema.AddSchema, *schema.DropSchema:
			return fmt.Errorf("%T is not allowed when migration plan is scoped to one schema", c)
		case *schema.AddTable:
			t = c.T
		case *schema.ModifyTable:
			t = c.T
		case *schema.DropTable:
			t = c.T
		default:
			continue
		}
		if t.Schema != nil && t.Schema.Name != "" {
			names[t.Schema.Name] = struct{}{}
		}
		for _, c := range t.Columns {
			e, ok := c.Type.Type.(*schema.EnumType)
			if ok && e.Schema != nil && e.Schema.Name != "" {
				names[t.Schema.Name] = struct{}{}
			}
		}
	}
	if len(names) > 1 {
		ks := make([]string, 0, len(names))
		for k := range names {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		return fmt.Errorf("found %d schemas when migration plan is scoped to one: %q", len(names), ks)
	}
	return nil
}

// byKeys sorts a map by keys.
func byKeys[T any](m map[string]T) []struct {
	K string
	V T
} {
	vs := make([]struct {
		K string
		V T
	}, 0, len(m))
	for k, v := range m {
		vs = append(vs, struct {
			K string
			V T
		}{k, v})
	}
	sort.Slice(vs, func(i, j int) bool {
		return vs[i].K < vs[j].K
	})
	return vs
}

// SortOptions allows drivers to customize the behavior of the SortChanges function.
type SortOptions struct {
	// FuncDepT reports if a function depends on the given table.
	FuncDepT func(*schema.Func, *schema.Table) bool
	// FuncDepV reports if a function depends on the given view.
	FuncDepV func(*schema.Func, *schema.View) bool
	// FuncDepO reports if a function depends on the given object.
	FuncDepO func(*schema.Func, schema.Object) bool
	// DefaultSchema defines the default schema (also known as "search_path") that
	// is used by the database to search for objects if no qualifier is provided.
	DefaultSchema string
}

// SortChanges is a helper function to sort to level changes based on their priority.
func SortChanges(changes []schema.Change, opts *SortOptions) []schema.Change {
	var views, drop, other []schema.Change
	for _, c := range changes {
		switch c.(type) {
		case *schema.AddView, *schema.DropView, *schema.ModifyView:
			views = append(views, c)
		case *schema.DropSchema, *schema.DropTable, *schema.DropFunc, *schema.DropProc, *schema.DropObject:
			drop = append(drop, c)
		default:
			other = append(other, c)
		}
	}
	if planned, err := sortViewChanges(views); err == nil { // no cycles.
		views = planned
	}
	// To keep backwards compatibility with previous sorting and also in case we miss any dependency between changes
	// (see, dependsOn function) we push views and drop changes to the end, unless there is a dependency requirement.
	changes = append(other, append(views, drop...)...)
	edges := make(map[schema.Change][]schema.Change)
	for _, c1 := range changes {
		for _, c2 := range changes {
			if c1 != c2 && dependsOn(c1, c2, V(opts)) {
				edges[c1] = append(edges[c1], c2)
			}
		}
	}
	var (
		add     func(schema.Change)
		added   = make(map[schema.Change]bool)
		planned = make([]schema.Change, 0, len(changes))
	)
	add = func(c schema.Change) {
		if added[c] {
			return
		}
		added[c] = true
		for _, d := range edges[c] {
			if !added[d] {
				add(d)
			}
		}
		planned = append(planned, c)
	}
	for _, c := range changes {
		if !added[c] {
			add(c)
		}
	}
	return planned
}

type (
	// Depender can be implemented by an object to determine if a change to it
	// depends on other change, or if other change depends on it. For example:
	// A table creation depends on type creation, and a type deletion depends on
	// table deletion.
	Depender interface {
		DependsOn(change, other schema.Change) bool
		DependencyOf(change, other schema.Change) bool
	}
	// RowTyper can be implemented by a type to determine if its source
	// is a regular table (e.g., row types).
	RowTyper interface {
		RowType() *schema.Table
	}
)

// dependsOn reports if the given change depends on the other change.
func dependsOn(c1, c2 schema.Change, opts SortOptions) bool {
	if dependOnOf(c1, c2) {
		return true
	}
	switch c1 := c1.(type) {
	case *schema.DropSchema:
		switch c2 := c2.(type) {
		case *schema.DropFunc:
			return SameSchema(c1.S, c2.F.Schema)
		case *schema.DropProc:
			return SameSchema(c1.S, c2.P.Schema)
		case *schema.DropTable:
			// Schema must be dropped after all its tables and references to them.
			return SameSchema(c1.S, c2.T.Schema) || slices.ContainsFunc(c2.T.ForeignKeys, func(fk *schema.ForeignKey) bool {
				return SameSchema(c1.S, fk.RefTable.Schema)
			})
		case *schema.ModifyTable:
			return SameSchema(c1.S, c2.T.Schema) || slices.ContainsFunc(c2.Changes, func(c schema.Change) bool {
				fk, ok := c.(*schema.DropForeignKey)
				return ok && SameSchema(c1.S, fk.F.RefTable.Schema)
			})
		case *schema.DropView:
			return SameSchema(c1.S, c2.V.Schema)
		}
	case *schema.AddTable:
		switch c2 := c2.(type) {
		case *schema.AddSchema:
			return c1.T.Schema.Name == c2.S.Name
		case *schema.DropTable:
			// Table recreation.
			return c1.T.Name == c2.T.Name && SameSchema(c1.T.Schema, c2.T.Schema)
		case *schema.AddTable:
			if refTo(c1.T.ForeignKeys, c2.T) {
				return true
			}
			if slices.ContainsFunc(c1.T.Columns, func(c *schema.Column) bool {
				return c.Type != nil && typeDependsOnT(c.Type.Type, c2.T)
			}) {
				return true
			}
		case *schema.ModifyTable:
			if (c1.T.Name != c2.T.Name || !SameSchema(c1.T.Schema, c2.T.Schema)) && refTo(c1.T.ForeignKeys, c2.T) {
				return true
			}
		case *schema.AddObject:
			t, ok := c2.O.(schema.Type)
			if ok && slices.ContainsFunc(c1.T.Columns, func(c *schema.Column) bool {
				return dependsOnT(c.Type.Type, t)
			}) {
				return true
			}
		case *schema.AddFunc:
			return tableDepFunc(c1.T, c2.F, opts)
		}
		return depOfAdd(c1.T.Deps, c2)
	case *schema.DropTable:
		// If it is a drop of a table, the change must occur
		// after all resources that rely on it will be dropped.
		switch c2 := c2.(type) {
		case *schema.DropTable:
			// References to this table, must be dropped first.
			if refTo(c2.T.ForeignKeys, c1.T) {
				return true
			}
			if slices.ContainsFunc(c2.T.Columns, func(c *schema.Column) bool {
				return c.Type != nil && typeDependsOnT(c.Type.Type, c1.T)
			}) {
				return true
			}
		case *schema.ModifyTable:
			if slices.ContainsFunc(c2.Changes, func(c schema.Change) bool {
				switch c := c.(type) {
				case *schema.DropForeignKey:
					return refTo([]*schema.ForeignKey{c.F}, c1.T)
				case *schema.DropColumn:
					return c.C.Type != nil && typeDependsOnT(c.C.Type.Type, c1.T)
				}
				return false
			}) {
				return true
			}
		case *schema.DropTrigger:
			if SameTable(c2.T.Table, c1.T) {
				return true
			}
		case *schema.DropFunc:
			if c2.F.Ret != nil && typeDependsOnT(c2.F.Ret, c1.T) || slices.ContainsFunc(c2.F.Args, func(f *schema.FuncArg) bool {
				return typeDependsOnT(f.Type, c1.T)
			}) {
				return true
			}
		case *schema.DropProc:
			if slices.ContainsFunc(c2.P.Args, func(f *schema.FuncArg) bool {
				return typeDependsOnT(f.Type, c1.T)
			}) {
				return true
			}
		}
		return depOfDrop(c1.T, c2)
	case *schema.ModifyTable:
		switch c2 := c2.(type) {
		case *schema.AddTable:
			// Table modification relies on its creation.
			if c1.T.Name == c2.T.Name && SameSchema(c1.T.Schema, c2.T.Schema) {
				return true
			}
			// Tables need to be created before referencing them.
			if slices.ContainsFunc(c1.Changes, func(c schema.Change) bool {
				switch c := c.(type) {
				case *schema.AddForeignKey:
					return refTo([]*schema.ForeignKey{c.F}, c2.T)
				case *schema.AddColumn:
					return c.C.Type != nil && typeDependsOnT(c.C.Type.Type, c2.T)
				case *schema.ModifyColumn:
					return c.To.Type != nil && typeDependsOnT(c.To.Type.Type, c2.T)
				}
				return false
			}) {
				return true
			}
		case *schema.ModifyTable:
			if c1.T != c2.T {
				addC := make(map[*schema.Column]bool)
				for _, c := range c2.Changes {
					if add, ok := c.(*schema.AddColumn); ok {
						addC[add.C] = true
					}
				}
				return slices.ContainsFunc(c1.Changes, func(c schema.Change) bool {
					fk, ok := c.(*schema.AddForeignKey)
					return ok && refTo([]*schema.ForeignKey{fk.F}, c2.T) && slices.ContainsFunc(fk.F.Columns, func(c *schema.Column) bool { return addC[c] })
				})
			}
		case *schema.AddObject:
			t, ok := c2.O.(schema.Type)
			if ok && slices.ContainsFunc(c1.Changes, func(c schema.Change) bool {
				switch c := c.(type) {
				case *schema.AddColumn:
					return dependsOnT(c.C.Type.Type, t)
				case *schema.ModifyColumn:
					return dependsOnT(c.To.Type.Type, t)
				default:
					return false
				}
			}) {
				return true
			}
		case *schema.DropTrigger:
			if SameTable(c1.T, c2.T.Table) {
				depC := make(map[string]bool)
				for _, ev := range c2.T.Events {
					for _, c := range ev.Columns {
						depC[c.Name] = true
					}
				}
				if slices.ContainsFunc(c1.Changes, func(c schema.Change) bool {
					// In case a column of the associated table is dropped,
					// the trigger should be dropped first if it depends on it.
					d, ok := c.(*schema.DropColumn)
					return ok && depC[d.C.Name]
				}) {
					return true
				}
			}
		}
		return depOfAdd(c1.T.Deps, c2)
	case *schema.AddView:
		switch c2 := c2.(type) {
		case *schema.AddSchema:
			return c1.V.Schema.Name == c2.S.Name
		case *schema.DropView:
			return c1.V.Name == c2.V.Name && SameSchema(c1.V.Schema, c2.V.Schema) // View recreation.
		case *schema.AddObject:
			t, ok := c2.O.(schema.Type)
			if ok && slices.ContainsFunc(c1.V.Columns, func(c *schema.Column) bool {
				return dependsOnT(c.Type.Type, t)
			}) {
				return true
			}
		}
		return depOfAdd(c1.V.Deps, c2)
	case *schema.DropView:
		if c2, ok := c2.(*schema.DropTrigger); ok && SameView(c2.T.View, c1.V) {
			return true
		}
		return depOfDrop(c1.V, c2)
	case *schema.ModifyView:
		if c2, ok := c2.(*schema.AddView); ok {
			// View modification relies on its creation.
			return c1.From.Name == c2.V.Name && SameSchema(c1.From.Schema, c2.V.Schema)
		}
		return depOfAdd(c1.To.Deps, c2)
	case *schema.AddFunc:
		if c2, ok := c2.(*schema.ModifyTable); ok {
			// Check if the modification of a table relies on the function.
			if slices.ContainsFunc(c2.Changes, func(c schema.Change) bool {
				add, ok := c.(*schema.AddCheck)
				return ok && ContainsCall(&schema.Func{Schema: c2.T.Schema, Body: add.C.Expr}, c1.F, opts)
			}) {
				return false
			}
		}
		if depOfAdd(c1.F.Deps, c2) {
			return true
		}
		switch c2 := c2.(type) {
		case *schema.AddSchema:
			return c1.F.Schema.Name == c2.S.Name
		case *schema.DropFunc:
			return c1.F.Name == c2.F.Name && SameSchema(c1.F.Schema, c2.F.Schema) // Func recreation.
		case *schema.AddFunc:
			if funcDep(c1.F, c2.F, opts) {
				return true // Relies on other function or overload.
			}
		case *schema.ModifyFunc:
			if funcDep(c1.F, c2.To, opts) {
				return true // Relies on the new definition.
			}
		case *schema.AddTable:
			if opts.FuncDepT != nil && opts.FuncDepT(c1.F, c2.T) {
				return true
			}
			if c1.F.Ret != nil && typeDependsOnT(c1.F.Ret, c2.T) || slices.ContainsFunc(c1.F.Args, func(f *schema.FuncArg) bool {
				return typeDependsOnT(f.Type, c2.T)
			}) {
				return true
			}
		case *schema.AddView:
			if opts.FuncDepV != nil && opts.FuncDepV(c1.F, c2.V) {
				return true
			}
		case *schema.AddObject:
			t, ok := c2.O.(schema.Type)
			if ok && (c1.F.Ret == t || slices.ContainsFunc(c1.F.Args, func(f *schema.FuncArg) bool {
				return dependsOnT(f.Type, t)
			})) {
				return true
			}
		}
		// If object is not defined explicitly in the depends_on list,
		// and not detected by the cases above, it is not a dependency.
		return false
	case *schema.DropFunc:
		switch c2 := c2.(type) {
		case *schema.DropFunc:
			if funcDep(c2.F, c1.F, opts) {
				// If f1 depends on f2, f1 should be dropped before f2.
				return true
			}
		case *schema.ModifyFunc:
			if funcDep(c2.From, c1.F, opts) {
				// If f1 depends on previous definition of f2, f1 should be dropped before f2.
				return true
			}
		case *schema.ModifyTable:
			// We need to drop the check constraint before dropping the function.
			if slices.ContainsFunc(c2.Changes, func(c schema.Change) bool {
				drop, ok := c.(*schema.DropCheck)
				return ok && ContainsCall(&schema.Func{Schema: c2.T.Schema, Body: drop.C.Expr}, c1.F, opts)
			}) {
				return true
			}
		}
		return depOfDrop(c1.F, c2)
	case *schema.ModifyFunc:
		switch c2 := c2.(type) {
		case *schema.AddFunc:
			if c1.From.Name == c2.F.Name && SameSchema(c1.From.Schema, c2.F.Schema) {
				return true // Func modification relies on its creation.
			}
			if funcDep(c1.To, c2.F, opts) {
				return true // New definition relies on a new function.
			}
		case *schema.ModifyFunc:
			if funcDep(c1.To, c2.To, opts) {
				return true // New definition relies on a new definition.
			}
		}
		return depOfAdd(c1.To.Deps, c2)
	case *schema.AddProc:
		switch c2 := c2.(type) {
		case *schema.AddSchema:
			return c1.P.Schema.Name == c2.S.Name
		case *schema.AddTable:
			if slices.ContainsFunc(c1.P.Args, func(f *schema.FuncArg) bool {
				return typeDependsOnT(f.Type, c2.T)
			}) {
				return true
			}
		case *schema.DropProc:
			return c1.P.Name == c2.P.Name && SameSchema(c1.P.Schema, c2.P.Schema) // Proc recreation.
		case *schema.AddProc:
			if procDep(c1.P, c2.P, opts) {
				return true // Relies on other procedure or overload.
			}
		case *schema.ModifyProc:
			if procDep(c1.P, c2.To, opts) {
				return true // Relies on the new definition.
			}
		case *schema.AddObject:
			t, ok := c2.O.(schema.Type)
			if ok && slices.ContainsFunc(c1.P.Args, func(f *schema.FuncArg) bool {
				return dependsOnT(f.Type, t)
			}) {
				return true
			}
		}
	case *schema.DropProc:
		switch c2 := c2.(type) {
		case *schema.DropProc:
			if procDep(c2.P, c1.P, opts) {
				// If f1 depends on f2, f1 should be dropped before f2.
				return true
			}
		case *schema.ModifyProc:
			if procDep(c2.From, c1.P, opts) {
				// If f1 depends on previous definition of f2, f1 should be dropped before f2.
				return true
			}
		}
		return depOfDrop(c1.P, c2)
	case *schema.ModifyProc:
		switch c2 := c2.(type) {
		case *schema.AddProc:
			if c1.From.Name == c2.P.Name && SameSchema(c1.From.Schema, c2.P.Schema) {
				return true // Proc modification relies on its creation.
			}
			if procDep(c1.To, c2.P, opts) {
				return true // New definition relies on a new procedure.
			}
		case *schema.ModifyProc:
			if procDep(c1.To, c2.To, opts) {
				return true // New definition relies on a new definition.
			}
		}
		return depOfAdd(c1.To.Deps, c2)
	case *schema.DropObject:
		t, ok := c1.O.(schema.Type)
		if !ok {
			return false
		}
		// Dropping a type must occur after all its usage were dropped.
		switch c2 := c2.(type) {
		case *schema.DropView:
			// Dropping a view also drops its triggers and might depend on the type.
			if slices.ContainsFunc(c2.V.Triggers, func(tg *schema.Trigger) bool {
				return slices.Contains(tg.Deps, c1.O)
			}) {
				return true
			}
		case *schema.DropTable:
			// Dropping a table also drops its triggers and might depend on the type.
			if slices.ContainsFunc(c2.T.Triggers, func(tg *schema.Trigger) bool {
				return slices.Contains(tg.Deps, c1.O)
			}) {
				return true
			}
			if slices.ContainsFunc(c2.T.Columns, func(c *schema.Column) bool {
				return dependsOnT(c.Type.Type, t)
			}) {
				return true
			}
		case *schema.ModifyTable:
			return slices.ContainsFunc(c2.Changes, func(c schema.Change) bool {
				d, ok := c.(*schema.DropColumn)
				return ok && dependsOnT(d.C.Type.Type, t)
			})
		case *schema.DropFunc:
			return slices.Contains(c2.F.Deps, c1.O) || c2.F.Ret == t || slices.ContainsFunc(c2.F.Args, func(f *schema.FuncArg) bool {
				return dependsOnT(f.Type, t)
			})
		case *schema.DropProc:
			return slices.Contains(c2.P.Deps, c1.O) || slices.ContainsFunc(c2.P.Args, func(f *schema.FuncArg) bool {
				return dependsOnT(f.Type, t)
			})
		}
	case *schema.AddTrigger:
		switch c2 := c2.(type) {
		case *schema.AddTable:
			return SameTable(c1.T.Table, c2.T)
		case *schema.AddView:
			return SameView(c1.T.View, c2.V)
		case *schema.ModifyTable:
			if SameTable(c1.T.Table, c2.T) {
				depC := make(map[string]bool)
				for _, ev := range c1.T.Events {
					for _, c := range ev.Columns {
						depC[c.Name] = true
					}
				}
				// If the trigger depends on a column that on the changes list,
				// it should be created after the column.
				if slices.ContainsFunc(c2.Changes, func(c schema.Change) bool {
					switch c := c.(type) {
					case *schema.AddColumn:
						return depC[c.C.Name]
					case *schema.RenameColumn:
						return depC[c.To.Name]
					}
					return false
				}) {
					return true
				}
			}
		}
		return depOfAdd(c1.T.Deps, c2)
	case *schema.DropTrigger:
		return depOfDrop(c1.T, c2)
	case *schema.ModifyTrigger:
		return depOfAdd(c1.To.Deps, c2) || depOfDrop(c1.From, c2)
	}
	return false
}

// dependOnOf checks if the given change depends on the other change or
// vice versa based on their underlying object implementation.
func dependOnOf(change, other schema.Change) bool {
	switch change := change.(type) {
	case *schema.AddObject:
		if d, ok := change.O.(Depender); ok && d.DependsOn(change, other) {
			return true
		}
	case *schema.ModifyObject:
		if d, ok := change.To.(Depender); ok && d.DependsOn(change, other) {
			return true
		}
	case *schema.DropObject:
		if d, ok := change.O.(Depender); ok && d.DependsOn(change, other) {
			return true
		}
	}
	switch other := other.(type) {
	case *schema.AddObject:
		if d, ok := other.O.(Depender); ok && d.DependencyOf(other, change) {
			return true
		}
	case *schema.ModifyObject:
		if d, ok := other.To.(Depender); ok && d.DependencyOf(other, change) {
			return true
		}
	case *schema.DropObject:
		if d, ok := other.O.(Depender); ok && d.DependencyOf(other, change) {
			return true
		}
	}
	return false
}

// depOfDrops checks if the given object is a dependency of the given change.
func depOfDrop(o schema.Object, c schema.Change) bool {
	var deps []schema.Object
	switch c := c.(type) {
	case *schema.DropTable:
		deps = c.T.Deps
		for _, t := range c.T.Triggers {
			deps = append(deps, t.Deps...)
		}
	case *schema.DropView:
		deps = c.V.Deps
		for _, t := range c.V.Triggers {
			deps = append(deps, t.Deps...)
		}
	case *schema.DropFunc:
		deps = c.F.Deps
	case *schema.DropProc:
		deps = c.P.Deps
	case *schema.DropTrigger:
		deps = c.T.Deps
	}
	return slices.Contains(deps, o)
}

// depOfAdd checks if the given change is a creation of a resource exists in the given list.
func depOfAdd(refs []schema.Object, c schema.Change) bool {
	var o schema.Object
	switch c := c.(type) {
	case *schema.AddTable:
		return slices.ContainsFunc(refs, func(o schema.Object) bool {
			t, ok := o.(*schema.Table)
			return ok && SameTable(c.T, t)
		})
	case *schema.ModifyTable:
		return slices.ContainsFunc(refs, func(o schema.Object) bool {
			t, ok := o.(*schema.Table)
			return ok && SameTable(c.T, t)
		})
	case *schema.AddView:
		return slices.ContainsFunc(refs, func(o schema.Object) bool {
			v, ok := o.(*schema.View)
			return ok && SameView(c.V, v)
		})
	case *schema.AddObject:
		o = c.O
	case *schema.AddTrigger:
		o = c.T
	// Check functions and procedures by
	// names as they might have overloads.
	case *schema.AddFunc:
		return slices.ContainsFunc(refs, func(o schema.Object) bool {
			f, ok := o.(*schema.Func)
			return ok && c.F.Name == f.Name && SameSchema(c.F.Schema, f.Schema)
		})
	case *schema.AddProc:
		return slices.ContainsFunc(refs, func(o schema.Object) bool {
			f, ok := o.(*schema.Proc)
			return ok && c.P.Name == f.Name && SameSchema(c.P.Schema, f.Schema)
		})
	default:
		return false
	}
	return slices.Contains(refs, o)
}

// refTo reports if the given foreign keys reference the given table.
func refTo(fks []*schema.ForeignKey, to *schema.Table) bool {
	return slices.ContainsFunc(fks, func(fk *schema.ForeignKey) bool {
		return SameTable(fk.RefTable, to)
	})
}

// typeDependsOnT reports if the declaration of type t1 depends on the given change.
func typeDependsOnT(t schema.Type, tt *schema.Table) bool {
	rt, ok := schema.UnderlyingType(t).(RowTyper)
	if !ok {
		return false
	}
	return SameTable(rt.RowType(), tt)
}

// dependsOnT reports if t1 depends on t2.
func dependsOnT(t1, t2 schema.Type) bool {
	// Comparing might panic due to mismatch types.
	defer func() { recover() }()
	return t1 == t2 || schema.UnderlyingType(t1) == t2
}

// SameView reports if the two objects represent the same view.
func SameView(v1, v2 *schema.View) bool {
	if v1 == nil || v2 == nil {
		return v1 == v2
	}
	return v1.Name == v2.Name && SameSchema(v1.Schema, v2.Schema)
}

// SameTable reports if the two objects represent the same table.
func SameTable(t1, t2 *schema.Table) bool {
	if t1 == nil || t2 == nil {
		return t1 == t2
	}
	return t1.Name == t2.Name && SameSchema(t1.Schema, t2.Schema)
}

// SameSchema reports if the given schemas are the same.
// Objects can be different as they might reside in two
// different states (current and desired).
func SameSchema(s1, s2 *schema.Schema) bool {
	if s1 == nil || s2 == nil {
		return s1 == s2
	}
	return s1.Name == s2.Name
}
