package main

import (
	"flag"
	"log"
	"log/slog"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/components/producers"
	"github.com/smithy-security/smithy/pkg/sarif"
)

func main() {
	var producerLang string
	flag.StringVar(&producerLang, "language", "", "")

	if err := producers.ParseFlags(); err != nil {
		log.Fatal(err)
	}
	producers.Append = true

	inFile, err := producers.ReadInFile()
	if err != nil {
		log.Fatal(err)
	}
	results, err := processInput(string(inFile), producerLang)
	if err != nil {
		log.Fatal(err)
	}
	if err := writeOutput(results); err != nil {
		log.Fatal(err)
	}
}

func writeOutput(results map[string][]*v1.Issue) error {
	for _, issues := range results {
		slog.Info(
			"appending",
			slog.Int("issues", len(issues)),
			slog.String("tool", "snyk"),
		)
		if err := producers.WriteSmithyOut(
			"snyk",
			issues,
		); err != nil {
			slog.Error("error writing smithy out for the snyk tool", "err", err)
		}
	}
	if len(results) == 0 { // in case snyk had a clean scan
		slog.Info("writing snyk output without any findings")
		if err := producers.WriteSmithyOut(
			"snyk",
			[]*v1.Issue{},
		); err != nil {
			slog.Error("error writing smithy out for the snyk tool", "err", err)
		}
	}
	return nil
}

func processInput(input string, language string) (map[string][]*v1.Issue, error) {
	var (
		issues       []*sarif.SmithyIssueCollection
		extraCtxLang = sarif.ExtraContextLanguageUnspecified
		err          error
	)

	if language != "" {
		extraCtxLang = sarif.ExtraContextLanguage(language)
	}

	issues, err = sarif.ToSmithy(input, extraCtxLang)
	if err != nil {
		return nil, err
	}

	results := map[string][]*v1.Issue{}
	for _, output := range issues {
		results[output.ToolName] = append(results[output.ToolName], output.Issues...)
	}
	return results, nil
}
