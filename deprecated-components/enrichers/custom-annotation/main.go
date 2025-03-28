// Package main of the codeowners enricher
// handles enrichment of individual issues with
// the groups/usernames listed in the github repository
// CODEOWNERS files.
// Owners are matched against the "target" field of the issue
package main

import (
	"encoding/json"
	"flag"
	"log"
	"log/slog"
	"strings"

	"github.com/go-errors/errors"

	apiv1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/deprecated-components/enrichers"
)

var (
	defaultName = "custom-annotation"
	annotations string
	name        string
)

func enrichIssue(i *apiv1.Issue, annotations string) (*apiv1.EnrichedIssue, error) {
	enrichedIssue := apiv1.EnrichedIssue{}
	annotationMap := map[string]string{}
	if err := json.Unmarshal([]byte(annotations), &annotationMap); err != nil {
		return nil, errors.Errorf("could not unmarshall annotation object '%s' to map[string]string, err: %w", annotations, err)
	}
	enrichedIssue = apiv1.EnrichedIssue{
		RawIssue:    i,
		Annotations: annotationMap,
	}
	return &enrichedIssue, nil
}

func run(name, annotations string) error {
	res, err := enrichers.LoadData()
	if err != nil {
		return err
	}
	if annotations == "" {
		slog.Info("annotations is empty")
	}
	for _, r := range res {
		slog.Info("processing results for ", slog.Any("scan", r.ScanInfo))
		enrichedIssues := make([]*apiv1.EnrichedIssue, 0, len(res))
		for _, i := range r.GetIssues() {
			eI, err := enrichIssue(i, annotations)
			if err != nil {
				slog.Error(err.Error())
				continue
			}
			enrichedIssues = append(enrichedIssues, eI)
		}

		err := enrichers.WriteData(&apiv1.EnrichedLaunchToolResponse{
			OriginalResults: r,
			Issues:          enrichedIssues,
		}, strings.ReplaceAll(name, " ", "-"))
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	flag.StringVar(&annotations, "annotations", enrichers.LookupEnvOrString("ANNOTATIONS", "{}"), "what are the annotations this enricher will add to the issues")
	flag.StringVar(&name, "annotation-name", enrichers.LookupEnvOrString("NAME", defaultName), "what is the name this enricher will masquerade as")
	if err := enrichers.ParseFlags(); err != nil {
		log.Fatal(err)
	}
	if err := run(name, annotations); err != nil {
		log.Fatal(err)
	}
}
