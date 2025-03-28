// Package main of the cdxgen producer parses the CycloneDX output of cdxgen and
// create a singular Smithy issue from it
package main

import (
	"log"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/deprecated-components/producers"
	"github.com/smithy-security/smithy/pkg/cyclonedx"
)

func main() {
	if err := producers.ParseFlags(); err != nil {
		log.Fatal(err)
	}
	var results []*v1.Issue
	inFile, err := producers.ReadInFile()
	if err != nil {
		log.Fatalf("could not load file err:%s", err)
	}
	results, err = handleCycloneDX(inFile)
	if err != nil {
		log.Fatalf("could not parse cyclonedx document err:%s", err)
	}
	if err := producers.WriteSmithyOut(
		"cdxgen", results,
	); err != nil {
		log.Fatalf("could not write smithy out err:%s", err)
	}
}

func handleCycloneDX(inFile []byte) ([]*v1.Issue, error) {
	return cyclonedx.ToSmithy(inFile, "json", "")
}
