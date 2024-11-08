package main

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/go-errors/errors"

	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

type (
	customAnnotationEnricher struct{}

	CustomAnnotation struct {
		Foo string `json:"foo"`
	}
)

func (m *customAnnotationEnricher) Annotate(
	ctx context.Context,
	findings []*ocsf.VulnerabilityFinding,
) ([]*ocsf.VulnerabilityFinding, error) {
	var newFindings = slices.Clone(findings)

	for idx := range newFindings {
		b, err := json.Marshal(CustomAnnotation{Foo: "bar"})
		if err != nil {
			return nil, errors.Errorf("could not json marshal custom annotation: %w", err)
		}
		newFindings[idx].Enrichments = append(newFindings[idx].Enrichments, &ocsf.Enrichment{
			Name:  "custom-annotation",
			Value: string(b),
		})
	}

	return newFindings, nil
}
