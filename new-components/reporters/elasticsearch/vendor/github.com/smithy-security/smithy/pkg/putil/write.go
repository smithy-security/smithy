package putil

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	v1 "github.com/smithy-security/smithy/api/proto/v1"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// WriteEnrichedResults writes the given enriched results to the given output file.
func WriteEnrichedResults(
	originalResults *v1.LaunchToolResponse,
	enrichedIssues []*v1.EnrichedIssue,
	outFile string,
) error {
	if err := os.MkdirAll(filepath.Dir(outFile), os.ModePerm); err != nil {
		return err
	}
	out := v1.EnrichedLaunchToolResponse{
		OriginalResults: originalResults,
		Issues:          enrichedIssues,
	}
	outBytes, err := proto.Marshal(&out)
	if err != nil {
		return err
	}
	if err := os.WriteFile(outFile, outBytes, 0o600); err != nil {
		return err
	}

	log.Printf("wrote %d enriched issues to %s", len(enrichedIssues), outFile)
	return nil
}

// WriteResults writes the given issues to the the given output file as the given tool name.
func WriteResults(
	toolName string,
	issues []*v1.Issue,
	outFile string,
	scanUUID string,
	scanStartTime time.Time,
	scanTags map[string]string,
) error {
	if err := os.MkdirAll(filepath.Dir(outFile), os.ModePerm); err != nil {
		return err
	}
	timestamp := timestamppb.New(scanStartTime)

	scanInfo := v1.ScanInfo{
		ScanUuid:      scanUUID,
		ScanStartTime: timestamp,
		ScanTags:      scanTags,
	}
	out := v1.LaunchToolResponse{
		ScanInfo: &scanInfo,
		ToolName: toolName,
		Issues:   issues,
	}

	outBytes, err := proto.Marshal(&out)
	if err != nil {
		return err
	}

	if err := os.WriteFile(outFile, outBytes, 0o600); err != nil {
		return fmt.Errorf("could not write to file '%s': %w", outFile, err)
	}

	log.Printf("wrote %d issues to %s", len(issues), outFile)
	return nil
}

// AppendResults appends the given issues to the existing output file.
func AppendResults(issues []*v1.Issue, outFile string) error {
	outBytes, err := os.ReadFile(outFile)
	if err != nil {
		return fmt.Errorf("could not read file '%s': %w", outFile, err)
	}

	out := v1.LaunchToolResponse{}
	if err := proto.Unmarshal(outBytes, &out); err != nil {
		return fmt.Errorf("could not unmarshal contents of file '%s': %w", outFile, err)
	}

	out.Issues = append(out.Issues, issues...)

	outBytes, err = proto.Marshal(&out)
	if err != nil {
		return err
	}

	if err := os.WriteFile(outFile, outBytes, 0o600); err != nil {
		return fmt.Errorf("could not write to file '%s': %w", outFile, err)
	}

	log.Printf("appended %d issues (now %d) to %s", len(issues), len(out.Issues), outFile)
	return nil
}
