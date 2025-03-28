// Package main of the codeowners enricher
// handles enrichment of individual issues with
// the groups/usernames listed in the github repository
// CODEOWNERS files.
// Owners are matched against the "target" field of the issue
package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"path/filepath"
	"strings"

	owners "github.com/hairyhenderson/go-codeowners"

	apiv1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/deprecated-components/enrichers"
)

const defaultAnnotation = "Owner"

var (
	repoBasePath string
	annotation   string
)

func enrichIssue(i *apiv1.Issue) (*apiv1.EnrichedIssue, error) {
	enrichedIssue := apiv1.EnrichedIssue{}
	annotations := map[string]string{}
	targets := []string{}
	if i.GetCycloneDXSBOM() != "" {
		// shortcut, if there is a CycloneDX BOM then there is no target.
		// we get the url from the repoURL parameter
		targets = []string{"."}
	} else {
		target := strings.Split(i.GetTarget(), ":")
		if len(target) > 1 {
			targets = append(targets, target[0])
		} else {
			targets = append(targets, i.GetTarget())
		}
	}
	for _, target := range targets {
		path := filepath.Join(repoBasePath, target)
		c, err := owners.FromFile(repoBasePath)
		if err != nil {
			log.Println("could not instantiate owners for path", path, "err", err)
			continue
		}
		owners := c.Owners(path)
		for _, owner := range owners {
			annotations[fmt.Sprintf("Owner-%d", len(annotations))] = owner
		}
	}
	enrichedIssue = apiv1.EnrichedIssue{
		RawIssue:    i,
		Annotations: annotations,
	}
	enrichedIssue.Annotations = annotations
	return &enrichedIssue, nil
}

func run() error {
	res, err := enrichers.LoadData()
	if err != nil {
		return err
	}
	if annotation == "" {
		annotation = defaultAnnotation
	}
	for _, r := range res {
		enrichedIssues := []*apiv1.EnrichedIssue{}
		for _, i := range r.GetIssues() {
			eI, err := enrichIssue(i)
			if err != nil {
				slog.Error(err.Error())
				continue
			}
			enrichedIssues = append(enrichedIssues, eI)
		}

		err := enrichers.WriteData(&apiv1.EnrichedLaunchToolResponse{
			OriginalResults: r,
			Issues:          enrichedIssues,
		}, "codeowners")
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	flag.StringVar(&annotation, "annotation", enrichers.LookupEnvOrString("ANNOTATION", defaultAnnotation), "what is the annotation this enricher will add to the issues, by default `Enriched Licenses`")
	flag.StringVar(&repoBasePath, "repoBasePath", enrichers.LookupEnvOrString("REPO_BASE_PATH", ""), `the base path of the repository, this is most likely an internally set variable`)

	if err := enrichers.ParseFlags(); err != nil {
		log.Fatal(err)
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
