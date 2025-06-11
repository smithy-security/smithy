package annotation

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/env"

	"github.com/smithy-security/smithy/sdk/component"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

type (
	// Conf contains the annotation configuration.
	Conf struct {
		AnnotationName       string
		AnnotationValuesJSON string
	}

	customAnnotator struct {
		conf *Conf
	}
)

const defaultEmptyJsonObject = "{}"

// NewConf initialises the enricher configuration from environment variables.
func NewConf() (*Conf, error) {
	var (
		cfg = &Conf{}
		err error
	)

	cfg.AnnotationName, err = env.GetOrDefault(
		"CUSTOM_ANNOTATION_NAME",
		"custom-annotation",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	annotationValues, err := env.GetOrDefault(
		"CUSTOM_ANNOTATION_VALUES",
		"{}",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	if annotationValues != defaultEmptyJsonObject {
		var m = make(map[string]any)
		if err := json.Unmarshal([]byte(annotationValues), &m); err != nil {
			return nil, errors.Errorf("invalid JSON values supplied '%s': %w", annotationValues, err)
		}
		cfg.AnnotationValuesJSON = annotationValues
	}

	return cfg, nil
}

// NewCustomAnnotator returns a new custom annotator.
func NewCustomAnnotator(conf *Conf) (*customAnnotator, error) {
	switch {
	case conf == nil:
		return nil, errors.New("nil annotation configuration")
	case conf.AnnotationName == "":
		return nil, errors.New("annotation name cannot be empty")
	}
	return &customAnnotator{
		conf: conf,
	}, nil
}

// Annotate adds annotated values to passed findings.
func (ca *customAnnotator) Annotate(
	ctx context.Context,
	findings []*vf.VulnerabilityFinding,
) ([]*vf.VulnerabilityFinding, error) {
	var (
		providerName = "custom-annotation-enricher"
		logger       = component.LoggerFromContext(ctx).
				With(slog.Int("num_findings", len(findings))).
				With(slog.String("provider_name", providerName)).
				With(slog.String("annotation_name", ca.conf.AnnotationName)).
				With(slog.Any("annotation_values", ca.conf.AnnotationValuesJSON))
	)

	logger.Debug("preparing to annotate findings...")

	for idx := range findings {
		findings[idx].Finding.Enrichments = append(
			findings[idx].Finding.Enrichments,
			&ocsf.Enrichment{
				Name:     ca.conf.AnnotationName,
				Value:    ca.conf.AnnotationValuesJSON,
				Type:     &providerName,
				Provider: &providerName,
			},
		)
	}

	logger.Debug("findings annotated successfully!")
	return findings, nil
}
