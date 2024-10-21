// Package main implements the binary for
// parsing trufflehog results into the smithy format
package main

import (
	"fmt"
	"log"

	"github.com/mitchellh/mapstructure"

	v1 "github.com/smithy-security/smithy/api/proto/v1"

	"github.com/smithy-security/smithy/components/producers"
)

func main() {
	if err := producers.ParseFlags(); err != nil {
		log.Fatal(err)
	}

	inFile, err := producers.ReadInFile()
	if err != nil {
		log.Fatal(err)
	}

	results, err := producers.ParseMultiJSONMessages(inFile)
	if err != nil {
		log.Fatal(err)
	}
	truffleResults := make([]TrufflehogOut, len(results))
	for i, r := range results {
		var x TrufflehogOut
		err := mapstructure.Decode(r, &x)
		if err != nil {
			log.Fatal(err)
		}
		truffleResults[i] = x
	}
	issues, err := parseIssues(truffleResults)
	if err != nil {
		log.Fatal(err)
	}
	if err := producers.WriteSmithyOut(
		"trufflehog",
		issues,
	); err != nil {
		log.Fatal(err)
	}
}

func parseIssues(out []TrufflehogOut) ([]*v1.Issue, error) {
	issues := []*v1.Issue{}

	for _, r := range out {
		confidence := v1.Confidence_CONFIDENCE_MEDIUM
		if r.Verified {
			confidence = v1.Confidence_CONFIDENCE_HIGH
		}
		var target, description string
		if r.SourceMetadata.Data.Filesystem.File != "" {
			target = r.SourceMetadata.Data.Filesystem.File
			description = fmt.Sprintf("Raw:%s\nRedacted:%s\n", r.Raw, r.Redacted)
		} else {
			target = fmt.Sprintf("%s:%s:%s:%d", r.SourceMetadata.Data.Git.Repository, r.SourceMetadata.Data.Git.Commit, r.SourceMetadata.Data.Git.File, r.SourceMetadata.Data.Git.Line)
			description = fmt.Sprintf("Raw:%s\nRedacted:%s\nTimestamp:%s\nEmail:%s\n", r.Raw, r.Redacted, r.SourceMetadata.Data.Git.Timestamp, r.SourceMetadata.Data.Git.Email)
		}
		raw := r.Raw
		iss := &v1.Issue{
			Target:         target,
			Type:           r.SourceName,
			Title:          fmt.Sprintf("%s - %s", r.DecoderName, r.DetectorName),
			Severity:       v1.Severity_SEVERITY_UNSPECIFIED,
			Cvss:           0.0,
			Confidence:     confidence,
			Description:    description,
			ContextSegment: &raw,
		}
		issues = append(issues, iss)
	}
	return issues, nil
}

// TrufflehogOut represents the output of a Trufflehog run
type TrufflehogOut struct {
	SourceMetadata TruffleSourceMeta
	SourceID       int64
	SourceType     int64
	SourceName     string
	DetectorType   int64
	DetectorName   string
	DecoderName    string
	Verified       bool
	Raw            string
	Redacted       string
}

// TruffleSourceMeta is the "SourceMetadata" part of the trufflehog results
type TruffleSourceMeta struct {
	Data TData
}

// TData is the "Data" part of the trufflehog source metadata results
type TData struct {
	Filesystem TFS
	Git        TGit
}

// TFS is the "Filesystem" part of the trufflehog source metadata results
type TFS struct {
	File string
}

// TGit is the "Git" part of the trufflehog source metadata results
type TGit struct {
	Commit     string
	File       string
	Email      string
	Repository string
	Timestamp  string
	Line       int64
}
