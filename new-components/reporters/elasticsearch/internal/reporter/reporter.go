package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/go-errors/errors"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/pkg/env"

	"github.com/smithy-security/smithy/sdk/component"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
)

type (
	Conf struct {
		ElasticsearchURL    string
		ElasticsearchIndex  string
		ElasticsearchApiKey string
	}

	esLogger struct {
		conf   *Conf
		client *elasticsearch.Client
	}

	esInfo struct {
		Version struct {
			Number string `json:"number"`
		} `json:"version"`
	}

	// ElasticsearchReporterOption allows customising the reporter.
	ElasticsearchReporterOption func(g *esLogger) error
)

// NewJsonLogger returns a new json logger.
func NewElasticsearchLogger(config *Conf, client *elasticsearch.Client) (*esLogger, error) {
	if config == nil {
		return nil, errors.Errorf("configuration is nil")
	}
	if client == nil {
		return nil, errors.Errorf("elasticsearch client is nil")
	}
	return &esLogger{
		client: client,
		conf:   config,
	}, nil
}

// NewConf returns a new configuration build from environment lookup.
func NewConf(envLoader env.Loader) (*Conf, error) {
	var envOpts = make([]env.ParseOption, 0)
	if envLoader != nil {
		envOpts = append(envOpts, env.WithLoader(envLoader))
	}
	esURL, err := env.GetOrDefault("ELASTICSEARCH_URL",
		"",
		append(envOpts, env.WithDefaultOnError(false))...)
	if err != nil {
		return nil, errors.Errorf("could not get env variable for ELASTICSEARCH_URL: %w", err)
	}

	index, err := env.GetOrDefault(
		"ELASTICSEARCH_INDEX",
		"",
		append(envOpts, env.WithDefaultOnError(false))...,
	)
	if err != nil {
		return nil, errors.Errorf("could not get env variable for ELASTICSEARCH_INDEX: %w", err)
	}

	apiKey, err := env.GetOrDefault(
		"ELASTICSEARCH_API_KEY",
		"",
		append(envOpts, env.WithDefaultOnError(false))...,
	)
	if err != nil {
		return nil, errors.Errorf("could not get env variable for ELASTICSEARCH_API_KEY: %w", err)
	}

	switch {
	case esURL == "":
		return nil, errors.Errorf("variable 'ELASTICSEARCH_URL' needs to be set")
	case index == "":
		return nil, errors.Errorf("variable 'ELASTICSEARCH_INDEX' needs to be set")
	case apiKey == "":
		return nil, errors.Errorf("variable 'ELASTICSEARCH_API_KEY' needs to be set")
	}

	return &Conf{
		ElasticsearchURL:    esURL,
		ElasticsearchIndex:  index,
		ElasticsearchApiKey: apiKey,
	}, nil
}

// Report logs the findings in json format in the target elastcisearch.
func (e esLogger) Report(ctx context.Context, findings []*vf.VulnerabilityFinding) error {
	logger := component.
		LoggerFromContext(ctx).
		With(slog.Int("num_findings", len(findings)))

	for _, finding := range findings {
		b, err := protojson.Marshal(finding.Finding)
		if err != nil {
			return errors.Errorf("could not json marshal finding: %w", err)
		}
		e.client.Index(e.conf.ElasticsearchIndex, bytes.NewBuffer(b))
		logger.Info("found finding", slog.String("finding", string(b)))
	}

	return nil
}

func dumpStringResponse(res *esapi.Response) string {
	return res.String()
}

func GetESClient(conf *Conf) (*elasticsearch.Client, error) {
	var es *elasticsearch.Client
	var err error

	es, err = elasticsearch.NewClient(elasticsearch.Config{
		APIKey: conf.ElasticsearchApiKey,
		Addresses: []string{
			conf.ElasticsearchURL,
		},
	})
	if err != nil {
		return nil, errors.Errorf("could not get elasticsearch client err: %w", err)
	}

	// prove connection by attempting to retrieve cluster info, this requires read access to the cluster info
	var info esInfo
	res, err := es.Info()
	if err != nil {
		return nil, errors.Errorf("could not get cluster information as proof of connection, err: %w, raw response: %s", err, dumpStringResponse(res))
	}
	if res.StatusCode != http.StatusOK || res.IsError() {
		return nil, errors.Errorf("could not contact Elasticsearch, attempted to retrieve cluster info and got status code: %d as a result, body: %s", res.StatusCode, dumpStringResponse(res))
	}

	slog.Debug("received info from elasticsearch successfully")
	body := json.NewDecoder(res.Body)
	if err := body.Decode(&info); err != nil {
		return nil, errors.Errorf("could not decode elasticsearch cluster information %w", err)
	}

	if len(info.Version.Number) > 0 && info.Version.Number[0] != '8' {
		return nil, errors.Errorf("unsupported elasticsearch server version %s only version 8.x is supported, got %s instead", info.Version.Number, info.Version.Number)
	}
	return es, nil
}
