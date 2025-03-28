package main

import (
	"bytes"
	"log"

	"github.com/smithy-security/smithy/deprecated-components/producers"
	"github.com/smithy-security/smithy/deprecated-components/producers/typescript-yarn-audit/types"
)

func main() {
	if err := producers.ParseFlags(); err != nil {
		log.Fatal(err)
	}

	inFile, err := producers.ReadInFile()
	if err != nil {
		log.Fatal(err)
	}

	// Assumes one report per line
	inLines := bytes.Split(inFile, []byte("\n"))
	report, errors := types.NewReport(inLines)

	// Individual errors should already be printed to logs
	if len(errors) > 0 {
		log.Fatalf("Errors creating Yarn Audit report: %d", len(errors))
	}

	if report != nil {
		if err := producers.WriteSmithyOut(
			"yarn-audit",
			report.AsIssues(),
		); err != nil {
			log.Fatal(err)
		}
	}
}
