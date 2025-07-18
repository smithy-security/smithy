package annotation

import (
	"context"
	"log/slog"
	"strings"

	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/env"

	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"
)

type (
	// Conf contains the annotation configuration.
	Conf struct {
		AnnotationName   string
		AnnotationValues map[string]string
	}

	customAnnotator struct {
		conf *Conf
	}
)

const defaultEmpty = ""

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
		"",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	if annotationValues != defaultEmpty {
		var m = make(map[string]string)
		for _, kv := range strings.Split(annotationValues, ",") {
			parts := strings.SplitN(kv, ":", 2)
			if len(parts) != 2 {
				return nil, errors.Errorf("invalid key:value pair '%s': %w", kv, err)
			}
			m[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
		cfg.AnnotationValues = m
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

func (ca *customAnnotator) flattenMap() string {
	var flattened []string
	if ca.conf.AnnotationValues == nil {
		return ""
	}
	for k, v := range ca.conf.AnnotationValues {
		if v == "" {
			ca.conf.AnnotationValues[k] = defaultEmpty
		}
		flattened = append(flattened, k+": "+v)
	}
	return strings.Join(flattened, ", ")
}

// Annotate adds annotated values to passed findings.
func (ca *customAnnotator) Annotate(
	ctx context.Context,
	findings []*vf.VulnerabilityFinding,
) ([]*vf.VulnerabilityFinding, error) {
	var (
		providerName = "custom-annotation-enricher"
		logger       = componentlogger.LoggerFromContext(ctx).
				With(slog.Int("num_findings", len(findings))).
				With(slog.String("provider_name", providerName)).
				With(slog.String("annotation_name", ca.conf.AnnotationName)).
				With(slog.Any("annotation_values", ca.conf.AnnotationValues))
	)

	logger.Debug("preparing to annotate findings...")
	flattenedValues := ca.flattenMap()
	for idx := range findings {
		findings[idx].Finding.Enrichments = append(
			findings[idx].Finding.Enrichments,
			&ocsf.Enrichment{
				Name:     ca.conf.AnnotationName,
				Value:    flattenedValues,
				Type:     &providerName,
				Provider: &providerName,
			},
		)
	}

	logger.Debug("findings annotated successfully!")
	return findings, nil
}
