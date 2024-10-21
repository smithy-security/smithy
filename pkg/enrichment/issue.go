package enrichment

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/pkg/db"
)

// GetHash returns the hash of an issue.
// TODO: return an err from this func.
func GetHash(i *v1.Issue) string {
	h := sha256.New()
	sourceNoRef := strings.Split(i.GetSource(), "?ref=")

	if _, err := io.WriteString(h, i.GetTarget()); err != nil {
		log.Fatalf("could not write target hash: %s", err)
	}
	if _, err := io.WriteString(h, i.GetType()); err != nil {
		log.Fatalf("could not write type hash: %s", err)
	}
	if _, err := io.WriteString(h, i.GetTitle()); err != nil {
		log.Fatalf("could not write title hash: %s", err)
	}
	if _, err := io.WriteString(h, sourceNoRef[0]); err != nil {
		log.Fatalf("could not write sourceNoRef hash :%s", err)
	}
	if _, err := io.WriteString(h, i.GetSeverity().String()); err != nil {
		log.Fatalf("could not write severity hash: %s", err)
	}
	if _, err := io.WriteString(h, fmt.Sprintf("%f", i.GetCvss())); err != nil {
		log.Fatalf("could not write cvss hash: %s", err)
	}
	if _, err := io.WriteString(h, i.GetConfidence().String()); err != nil {
		log.Fatalf("could not write confidence hash: %s", err)
	}
	if _, err := io.WriteString(h, i.GetDescription()); err != nil {
		log.Fatalf("could not write description hash: %s", err)
	}
	if _, err := io.WriteString(h, i.GetCve()); err != nil {
		log.Fatalf("could not write cve hash: %s", err)
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}

// NewEnrichedIssue returns a new enriched issue from a raw issue.
func NewEnrichedIssue(i *v1.Issue) *v1.EnrichedIssue {
	return &v1.EnrichedIssue{
		RawIssue:      i,
		FirstSeen:     timestamppb.Now(),
		Count:         1,
		FalsePositive: false,
		UpdatedAt:     timestamppb.Now(),
		Hash:          GetHash(i),
	}
}

// UpdateEnrichedIssue updates a given enriched issue.
func UpdateEnrichedIssue(i *v1.EnrichedIssue) *v1.EnrichedIssue {
	i.Count++
	i.UpdatedAt = timestamppb.Now()
	return i
}

// EnrichIssue enriches a given issue, returning an enriched issue once processed.
func EnrichIssue(conn *db.DB, i *v1.Issue) (*v1.EnrichedIssue, error) {
	hash := GetHash(i)
	enrichedIssue := NewEnrichedIssue(i)
	dBIssue, err := GetIssueByHash(conn, hash)
	if errors.Is(err, sql.ErrNoRows) {
		log.Printf("Issue %s is new, enriching \n", i.Uuid)
		// create issue
		enrichedIssue = NewEnrichedIssue(i)
		err := CreateIssue(context.Background(), conn, enrichedIssue)
		if err != nil {
			log.Println(err)
			return nil, err
		}
		return enrichedIssue, nil
	} else if err != nil {
		return nil, err
	}
	// updat current issue db specific annotations with what we have in the database
	enrichedIssue.FirstSeen = dBIssue.FirstSeen
	enrichedIssue.Count = dBIssue.Count
	enrichedIssue.FalsePositive = dBIssue.FalsePositive
	enrichedIssue.UpdatedAt = dBIssue.UpdatedAt
	// update issue
	enrichedIssue = UpdateEnrichedIssue(enrichedIssue)
	if err := UpdateIssue(context.Background(), conn, enrichedIssue); err != nil {
		return nil, err
	}
	return enrichedIssue, nil
}
