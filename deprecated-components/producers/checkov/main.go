package main

import (
	"flag"
	"log"

	"github.com/go-errors/errors"

	smithyv1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/deprecated-components/producers"
	"github.com/smithy-security/smithy/pkg/cyclonedx"
	"github.com/smithy-security/smithy/pkg/sarif"
)

// the CycloneDX target override
var target string

func main() {
	flag.StringVar(&target, "target", "", "The target being scanned, this will override the CycloneDX target and is useful for cases where you scan iac or a dockerfile for an application that you know it's purl")

	if err := producers.ParseFlags(); err != nil {
		log.Fatal(err)
	}

	inFile, err := producers.ReadInFile()
	if err != nil {
		log.Fatal(err)
	}
	if err := run(inFile, target); err != nil {
		log.Fatal(err)
	}
}

func run(inFile []byte, target string) error {
	sarifResults, sarifErr := handleSarif(inFile)
	cyclondxResults, cyclonedxErr := handleCycloneDX(inFile, target)
	var issues []*smithyv1.Issue
	if sarifErr == nil {
		issues = sarifResults
	} else if cyclonedxErr == nil {
		issues = cyclondxResults
	} else {
		return errors.Errorf("Could not parse input file as neither Sarif nor CycloneDX sarif error: %v, cyclonedx error: %v", sarifErr, cyclonedxErr)
	}
	return producers.WriteSmithyOut(
		"checkov",
		issues,
	)
}

func handleSarif(inFile []byte) ([]*smithyv1.Issue, error) {
	var sarifResults []*sarif.SmithyIssueCollection
	var smithyResults []*smithyv1.Issue
	sarifResults, err := sarif.ToSmithy(string(inFile), sarif.ExtraContextLanguageUnspecified)
	if err != nil {
		return smithyResults, err
	}
	for _, result := range sarifResults {
		smithyResults = append(smithyResults, result.Issues...)
	}
	return smithyResults, nil
}

func handleCycloneDX(inFile []byte, target string) ([]*smithyv1.Issue, error) {
	return cyclonedx.ToSmithy(inFile, "json", target)
}
