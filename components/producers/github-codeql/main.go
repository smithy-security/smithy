package main

import (
	"log"
	"os"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/components/producers"
	"github.com/smithy-security/smithy/pkg/sarif"
)

// LookupEnvOrString will return the value of the environment variable
// if it exists, otherwise it will return the default value.
func LookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func main() {
	if err := producers.ParseFlags(); err != nil {
		log.Fatal(err)
	}
	res, err := producers.ReadInFile()
	if err != nil {
		log.Fatal(err)
	}
	results, err := handleSarif(res)
	if err != nil {
		log.Fatal(err)
	}
	if err := producers.WriteSmithyOut(
		"github-codeql",
		results,
	); err != nil {
		log.Fatal(err)
	}
}

func handleSarif(inFile []byte) ([]*v1.Issue, error) {
	var sarifResults []*sarif.SmithyIssueCollection
	var smithyResults []*v1.Issue
	sarifResults, err := sarif.ToSmithy(string(inFile), sarif.ExtraContextLanguageUnspecified)
	if err != nil {
		return smithyResults, err
	}
	for _, result := range sarifResults {
		smithyResults = append(smithyResults, result.Issues...)
	}
	return smithyResults, nil
}
