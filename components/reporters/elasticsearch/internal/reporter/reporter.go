package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v9"
	"github.com/elastic/go-elasticsearch/v9/esapi"
	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/env"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"
	"google.golang.org/protobuf/encoding/protojson"

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

	esURL, err := env.GetOrDefault(
		"ELASTICSEARCH_URL",
		"",
		append(envOpts, env.WithDefaultOnError(false))...,
	)
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
	logger := componentlogger.
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

	slog.Debug("received information from elasticsearch successfully")
	body := json.NewDecoder(res.Body)
	if err := body.Decode(&info); err != nil {
		return nil, errors.Errorf("could not decode elasticsearch cluster information %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	logger := componentlogger.LoggerFromContext(ctx)

	logger.Debug("elasticsearch info",
		slog.String("version_number", info.Version.Number))

	parts := strings.Split(info.Version.Number, ".")
	if len(parts) == 0 {
		return nil, errors.Errorf("could not parse es version number: %s", info.Version.Number)
	}

	majorVersion := parts[0]
	if majorVersion != "9" {
		return nil, errors.Errorf("unsupported elasticsearch server version: only version 9.x is supported, got %s", info.Version.Number)
	}
	return es, nil
}
