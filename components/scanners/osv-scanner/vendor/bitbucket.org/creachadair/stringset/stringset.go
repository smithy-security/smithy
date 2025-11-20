// Package stringset implements a lightweight (finite) set of string values
// based on Go's built-in map.  A Set provides some convenience methods for
// common set operations.
//
// A nil Set is ready for use as an empty set.  The basic set methods (Diff,
// Intersect, Union, IsSubset, Map, Choose, Partition) do not mutate their
// arguments.  There are also mutating operations (Add, Discard, Pop, Remove,
// Update) that modify their receiver in-place.
//
// A Set can also be traversed and modified using the normal map operations.
// Being a map, a Set is not safe for concurrent access by multiple goroutines
// unless all the concurrent accesses are reads.
package stringset

import (
	"maps"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// A Set represents a set of string values.  A nil Set is a valid
// representation of an empty set.
type Set map[string]struct{}

// String implements the fmt.Stringer interface.  It renders s in standard set
// notation, e.g., ø for an empty set, {a, b, c} for a nonempty one.
func (s Set) String() string {
	if s.Empty() {
		return "ø"
	}
	elts := s.Elements()
	var out strings.Builder
	out.WriteString("{")
	out.WriteString(strconv.Quote(elts[0]))
	for _, elt := range elts[1:] {
		out.WriteString(", ")
		out.WriteString(strconv.Quote(elt))
	}
	out.WriteString("}")
	return out.String()
}

// bigSmall returns the bigger set as the first return value and the smaller as the second.
func bigSmall(s1, s2 Set) (Set, Set) {
	if len(s1) < len(s2) {
		return s2, s1
	}
	return s1, s2
}

// New returns a new set containing exactly the specified elements.
// Returns a non-nil empty Set if no elements are specified.
func New(elts ...string) Set {
	set := make(Set, len(elts))
	for _, elt := range elts {
		set[elt] = struct{}{}
	}
	return set
}

// NewSize returns a new empty set pre-sized to hold at least n elements.
// This is equivalent to make(Set, n) and will panic if n < 0.
func NewSize(n int) Set { return make(Set, n) }

// Len returns the number of elements in s.
func (s Set) Len() int { return len(s) }

// Elements returns an ordered slice of the elements in s.
func (s Set) Elements() []string {
	elts := s.Unordered()
	sort.Strings(elts)
	return elts
}

// Unordered returns an unordered slice of the elements in s.
func (s Set) Unordered() []string {
	if len(s) == 0 {
		return nil
	}
	elts := make([]string, 0, len(s))
	for elt := range s {
		elts = append(elts, elt)
	}
	return elts
}

// Clone returns a new Set distinct from s, containing the same elements.
func (s Set) Clone() Set {
	return maps.Clone(s)
}

// ContainsAny reports whether s contains one or more of the given elements.
// It is equivalent in meaning to
//
//	s.Intersects(stringset.New(elts...))
//
// but does not construct an intermediate set.
func (s Set) ContainsAny(elts ...string) bool {
	for _, key := range elts {
		if _, ok := s[key]; ok {
			return true
		}
	}
	return false
}

// Contains reports whether s contains (all) the given elements.
// It is equivalent in meaning to
//
//	New(elts...).IsSubset(s)
//
// but does not construct an intermediate set.
func (s Set) Contains(elts ...string) bool {
	for _, elt := range elts {
		if _, ok := s[elt]; !ok {
			return false
		}
	}
	return true
}

// IsSubset reports whether s is a subset of s2, s ⊆ s2.
func (s Set) IsSubset(s2 Set) bool {
	if len(s) > len(s2) {
		return false
	}
	for k := range s {
		if _, ok := s2[k]; !ok {
			return false
		}
	}
	return true
}

// Equals reports whether s is equal to s2, having exactly the same elements.
func (s Set) Equals(s2 Set) bool { return len(s) == len(s2) && s.IsSubset(s2) }

// Empty reports whether s is empty.
func (s Set) Empty() bool { return len(s) == 0 }

// Intersects reports whether the intersection s ∩ s2 is non-empty, without
// explicitly constructing the intersection.
func (s Set) Intersects(s2 Set) bool {
	s2, s = bigSmall(s, s2) // Iterate over the smaller set.
	for k := range s {
		if _, ok := s2[k]; ok {
			return true
		}
	}
	return false
}

// Union constructs the union s ∪ s2.
func (s Set) Union(s2 Set) Set {
	if s.Empty() {
		return s2
	} else if s2.Empty() {
		return s
	}
	s, s2 = bigSmall(s, s2) // Clone the bigger set first.
	set := s.Clone()
	for k := range s2 {
		set[k] = struct{}{}
	}
	return set
}

// Intersect constructs the intersection s ∩ s2.
func (s Set) Intersect(s2 Set) Set {
	if s.Empty() || s2.Empty() {
		return nil
	}
	s2, s = bigSmall(s, s2) // Iterate over the smaller set.
	set := make(Set)
	for k := range s {
		if _, ok := s2[k]; ok {
			set[k] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

// Diff constructs the set difference s \ s2.
func (s Set) Diff(s2 Set) Set {
	if s.Empty() || s2.Empty() {
		return s
	}
	set := make(Set)
	for k := range s {
		if _, ok := s2[k]; !ok {
			set[k] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

// SymDiff constructs the symmetric difference s ∆ s2.
// It is equivalent in meaning to (s ∪ s2) \ (s ∩ s2).
func (s Set) SymDiff(s2 Set) Set {
	return s.Union(s2).Diff(s.Intersect(s2))
}

// Update adds the elements of s2 to *s in-place, and reports whether anything
// was added.
// If *s == nil and s2 ≠ ø, a new set is allocated that is a copy of s2.
func (s *Set) Update(s2 Set) bool {
	in := len(*s)
	if *s == nil && len(s2) > 0 {
		*s = s2.Clone()
		return true
	}
	maps.Copy(*s, s2)
	return len(*s) != in
}

// Add adds the specified elements to *s in-place and reports whether anything
// was added.  If *s == nil, a new set equivalent to New(ss...) is stored in *s.
func (s *Set) Add(ss ...string) bool {
	if *s == nil {
		*s = New(ss...)
		return !s.Empty()
	}
	in := len(*s)
	for _, key := range ss {
		(*s)[key] = struct{}{}
	}
	return len(*s) != in
}

// Remove removes the elements of s2 from s in-place and reports whether
// anything was removed.
//
// Equivalent to s = s.Diff(s2), but does not allocate a new set.
func (s Set) Remove(s2 Set) bool {
	in := s.Len()
	for k := range s2 {
		if s.Empty() {
			break
		}
		delete(s, k)
	}
	return s.Len() != in
}

// Discard removes the elements of elts from s in-place and reports whether
// anything was removed.
//
// Equivalent to s.Remove(New(elts...)), but does not allocate an intermediate
// set for ss.
func (s Set) Discard(elts ...string) bool {
	in := s.Len()
	for _, elt := range elts {
		if s.Empty() {
			break
		}
		delete(s, elt)
	}
	return s.Len() != in
}

// Index returns the first offset of needle in elts, if it occurs; otherwise -1.
func Index(needle string, elts []string) int {
	for i, elt := range elts {
		if elt == needle {
			return i
		}
	}
	return -1
}

// Contains reports whether v contains s, for v having type Set, []string,
// map[string]T, or Keyer. It returns false if v's type does not have one of
// these forms.
func Contains(v any, s string) bool {
	switch t := v.(type) {
	case []string:
		return Index(s, t) >= 0
	case Set:
		return t.Contains(s)
	case Keyer:
		return Index(s, t.Keys()) >= 0
	}
	if m := reflect.ValueOf(v); m.IsValid() && m.Kind() == reflect.Map && m.Type().Key() == refType {
		return m.MapIndex(reflect.ValueOf(s)).IsValid()
	}
	return false
}

// A Keyer implements a Keys method that returns the keys of a collection such
// as a map or a Set.
type Keyer interface {
	// Keys returns the keys of the receiver, which may be nil.
	Keys() []string
}

var refType = reflect.TypeOf((*string)(nil)).Elem()

// FromKeys returns a Set of strings from v, which must either be a string,
// a []string, a map[string]T, or a Keyer. It returns nil if v's type does
// not have one of these forms.
func FromKeys(v any) Set {
	switch t := v.(type) {
	case string:
		return New(t)
	case []string:
		return New(t...)
	case map[string]struct{}: // includes Set
		result := make(Set, len(t))
		for key := range t {
			result[key] = struct{}{}
		}
		return result
	case Keyer:
		return New(t.Keys()...)
	case nil:
		return nil
	}
	m := reflect.ValueOf(v)
	if m.Kind() != reflect.Map || m.Type().Key() != refType {
		return nil
	}
	result := make(Set, m.Len())
	iter := m.MapRange()
	for iter.Next() {
		result.Add(iter.Key().String())
	}
	return result
}

// FromIndexed returns a Set constructed from the values of f(i) for
// each 0 ≤ i < n. If n ≤ 0 the result is nil.
func FromIndexed(n int, f func(int) string) Set {
	var set Set
	for i := 0; i < n; i++ {
		set.Add(f(i))
	}
	return set
}

// FromValues returns a Set of the values from v, which has type map[T]string.
// Returns the empty set if v does not have a type of this form.
func FromValues(v any) Set {
	if t := reflect.TypeOf(v); t == nil || t.Kind() != reflect.Map || t.Elem() != refType {
		return nil
	}
	var set Set
	m := reflect.ValueOf(v)
	iter := m.MapRange()
	for iter.Next() {
		set.Add(iter.Value().String())
	}
	return set
}

// Map returns the Set that results from applying f to each element of s.
func (s Set) Map(f func(string) string) Set {
	var out Set
	for k := range s {
		out.Add(f(k))
	}
	return out
}

// Each applies f to each element of s.
func (s Set) Each(f func(string)) {
	for k := range s {
		f(k)
	}
}

// Select returns the subset of s for which f returns true.
func (s Set) Select(f func(string) bool) Set {
	var out Set
	for k := range s {
		if f(k) {
			out.Add(k)
		}
	}
	return out
}

// Partition returns two disjoint sets, yes containing the subset of s for
// which f returns true and no containing the subset for which f returns false.
func (s Set) Partition(f func(string) bool) (yes, no Set) {
	for k := range s {
		if f(k) {
			yes.Add(k)
		} else {
			no.Add(k)
		}
	}
	return
}

// Choose returns an element of s for which f returns true, if one exists.  The
// second result reports whether such an element was found.
// If f == nil, chooses an arbitrary element of s. The element chosen is not
// guaranteed to be the same across repeated calls.
func (s Set) Choose(f func(string) bool) (string, bool) {
	if f == nil {
		for k := range s {
			return k, true
		}
	}
	for k := range s {
		if f(k) {
			return k, true
		}
	}
	return "", false
}

// Pop removes and returns an element of s for which f returns true, if one
// exists (essentially Choose + Discard).  The second result reports whether
// such an element was found.  If f == nil, pops an arbitrary element of s.
func (s Set) Pop(f func(string) bool) (string, bool) {
	if v, ok := s.Choose(f); ok {
		delete(s, v)
		return v, true
	}
	return "", false
}

// Count returns the number of elements of s for which f returns true.
func (s Set) Count(f func(string) bool) (n int) {
	for k := range s {
		if f(k) {
			n++
		}
	}
	return
}
