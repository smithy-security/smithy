package enrichment

import (
	"context"

	"time"

	"github.com/go-errors/errors"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/pkg/db"
)

type issue struct {
	Hash          string    `db:"hash"`
	FirstSeen     time.Time `db:"first_seen"`
	Occurrences   uint64    `db:"occurrences"`
	FalsePositive bool      `db:"false_positive"`
	UpdatedAt     time.Time `db:"updated_at"`

	Target      string  `db:"target"`
	Type        string  `db:"type"`
	Title       string  `db:"title"`
	Severity    int32   `db:"severity"`
	CVSS        float64 `db:"cvss"`
	Confidence  int32   `db:"confidence"`
	Description string  `db:"description"`
	Source      string  `db:"source"`
	CVE         string  `db:"cve"`
	UUID        string  `db:"uuid"`
}

func toDBIssue(i *v1.EnrichedIssue) (*issue, error) {
	firstSeen := i.GetFirstSeen().AsTime()
	updatedAt := i.GetUpdatedAt().AsTime()

	return &issue{
		Hash:          i.GetHash(),
		FirstSeen:     firstSeen,
		Occurrences:   i.GetCount(),
		FalsePositive: i.GetFalsePositive(),
		UpdatedAt:     updatedAt,
		Target:        i.RawIssue.GetTarget(),
		Type:          i.RawIssue.GetType(),
		Title:         i.RawIssue.GetTitle(),
		Severity:      int32(i.RawIssue.GetSeverity()),
		CVSS:          i.RawIssue.GetCvss(),
		Confidence:    int32(i.RawIssue.GetConfidence()),
		Description:   i.RawIssue.GetDescription(),
		Source:        i.RawIssue.GetSource(),
		CVE:           i.RawIssue.GetCve(),
		UUID:          i.RawIssue.GetUuid(),
	}, nil
}

func toEnrichedIssue(i *issue) (*v1.EnrichedIssue, error) {
	firstSeen := timestamppb.New(i.FirstSeen)
	updatedAt := timestamppb.New(i.UpdatedAt)

	return &v1.EnrichedIssue{
		Hash:          i.Hash,
		FirstSeen:     firstSeen,
		Count:         i.Occurrences,
		FalsePositive: i.FalsePositive,
		UpdatedAt:     updatedAt,
		RawIssue: &v1.Issue{
			Target:      i.Target,
			Type:        i.Type,
			Title:       i.Title,
			Severity:    v1.Severity(i.Severity),
			Cvss:        i.CVSS,
			Confidence:  v1.Confidence(i.Confidence),
			Description: i.Description,
			Source:      i.Source,
			Cve:         i.CVE,
			Uuid:        i.UUID,
		},
	}, nil
}

// GetIssueByHash returns an issue given its hash.
func GetIssueByHash(conn *db.DB, hash string) (*v1.EnrichedIssue, error) {
	i := issue{}
	if err := conn.Get(&i, `SELECT * FROM issues WHERE "hash"=$1`, hash); err != nil {
		return nil, err
	}
	return toEnrichedIssue(&i)
}

// Dump is an internal debug method.
func Dump(conn *db.DB) []*v1.EnrichedIssue {
	var i []*issue
	var res []*v1.EnrichedIssue
	if err := conn.Select(&i, `SELECT * FROM issues`); err != nil {
		panic(err)
	}
	for _, j := range i {
		a, e := toEnrichedIssue(j)
		if e != nil {
			panic(e)
		}
		res = append(res, a)
	}
	return res
}

// CreateIssue creates the given enriched issue on the database.
func CreateIssue(ctx context.Context, conn *db.DB, eI *v1.EnrichedIssue) error {
	tx, err := conn.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	i, err := toDBIssue(eI)
	if err != nil {
		return err
	}
	_, err = tx.NamedExec(`INSERT INTO
issues (
    "target",
    "type",
    "title",
    severity,
    cvss,
    confidence,
    "description",
    source,
    "hash",
    first_seen,
    occurrences,
    false_positive,
    updated_at,
    cve,
	uuid
) VALUES (
    :target,
    :type,
    :title,
    :severity,
    :cvss,
    :confidence,
    :description,
    :source,
    :hash,
    :first_seen,
    :occurrences,
    :false_positive,
    :updated_at,
    :cve,
	:uuid);`,
		map[string]interface{}{
			"target":         i.Target,
			"type":           i.Type,
			"title":          i.Title,
			"severity":       i.Severity,
			"cvss":           i.CVSS,
			"confidence":     i.Confidence,
			"description":    i.Description,
			"source":         i.Source,
			"hash":           i.Hash,
			"first_seen":     i.FirstSeen,
			"occurrences":    i.Occurrences,
			"false_positive": i.FalsePositive,
			"updated_at":     i.UpdatedAt,
			"cve":            i.CVE,
			"uuid":           i.UUID,
		},
	)
	if err != nil {
		if rErr := tx.Rollback(); rErr != nil {
			return errors.Errorf("could not rollback: %w: %w", rErr, err)
		}
		return err
	}
	return tx.Commit()
}

// UpdateIssue updates a given enriched issue on the database.
func UpdateIssue(ctx context.Context, conn *db.DB, eI *v1.EnrichedIssue) error {
	tx, err := conn.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}
	i, err := toDBIssue(eI)
	if err != nil {
		return err
	}
	_, err = tx.NamedExec(`UPDATE issues
SET
    occurrences=:occurrences,
    updated_at=:updated_at
WHERE "hash"=:hash;`,
		map[string]interface{}{
			"occurrences": i.Occurrences,
			"updated_at":  i.UpdatedAt,
			"hash":        i.Hash,
		},
	)
	if err != nil {
		if rErr := tx.Rollback(); rErr != nil {
			return errors.Errorf("could not rollback: %w: %w", rErr, err)
		}
		return err
	}
	return tx.Commit()
}

// DeleteIssueByHash deletes an issue given its hash.
func DeleteIssueByHash(conn *db.DB, hash string) error {
	if _, err := conn.NamedExec(`DELETE FROM issues WHERE "hash"=:hash`, map[string]interface{}{"hash": hash}); err != nil {
		return err
	}
	return nil
}
