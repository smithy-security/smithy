package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/Masterminds/semver/v3"
	esv8 "github.com/elastic/go-elasticsearch/v8"
	esv9 "github.com/elastic/go-elasticsearch/v9"
	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/env"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"
	"google.golang.org/protobuf/encoding/protojson"
)

type (
	// Conf is a struct to define the ES configuration
	Conf struct {
		ElasticsearchURL           string
		ElasticsearchIndex         string
		ElasticsearchAPIKey        string
		ElasticsearchServerVersion string
	}

	esInfo struct {
		Version struct {
			Number string `json:"number"`
		} `json:"version"`
	}

	elasticsearchReporter struct {
		conf   *Conf
		client esClient
	}

	// esClient is a common interface for the Elasticsearch clients
	esClient interface {
		Index(index string, body io.Reader) (esResponse, error)
	}

	// esResponse is a common interface for the Elasticsearch responses
	esResponse interface {
		IsError() bool
		String() string
		StatusCode() int
		Body() io.ReadCloser
	}

	clusterInfo interface {
		Info() (esResponse, error)
	}

	// Reporter is an interface for the findings report
	Reporter interface {
		Report(ctx context.Context, findings []*vf.VulnerabilityFinding) error
	}
)

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
		ElasticsearchAPIKey: apiKey,
	}, nil
}

// Report logs the findings in json format in the target elasticsearch
func (r *elasticsearchReporter) Report(ctx context.Context, findings []*vf.VulnerabilityFinding) error {
	logger := componentlogger.
		LoggerFromContext(ctx).
		With(slog.Int("num_findings", len(findings)))

	for _, finding := range findings {
		b, err := protojson.Marshal(finding.Finding)
		if err != nil {
			return errors.Errorf("could not json marshal finding: %w", err)
		}

		res, err := r.client.Index(r.conf.ElasticsearchIndex, bytes.NewBuffer(b))
		if err != nil {
			return errors.Errorf("could not index finding: %w", err)
		}
		if res.IsError() {
			return errors.Errorf("elasticsearch returned error: %s", res.String())
		}

		logger.Info("found finding", slog.String("finding", string(b)))
		res.Body().Close()
	}
	return nil
}

// New creates a new Reporter with automatic version detection.
// It starts with a v8 client, detects the server version, and upgrades to v9 if needed.
func New(ctx context.Context, conf *Conf) (Reporter, error) {
	logger := componentlogger.LoggerFromContext(ctx)

	// Start with thee v8 client for initial connection
	cfg := esv8.Config{
		APIKey:    conf.ElasticsearchAPIKey,
		Addresses: []string{conf.ElasticsearchURL},
	}
	client, err := esv8.NewClient(cfg)
	if err != nil {
		return nil, errors.Errorf("could not create elasticsearch v8 client: %w", err)
	}

	wrapper := &v8Client{client: client}
	info, err := getServerInfo(logger, wrapper)
	if err != nil {
		return nil, err
	}

	serverVer, err := semver.NewVersion(info.Version.Number)
	if err != nil {
		return nil, errors.Errorf("could not parse elasticsearch server version %q: %w", info.Version.Number, err)
	}

	serverMajorVersion := serverVer.Major()
	logger.Info("detected elasticsearch server version",
		slog.String("version", info.Version.Number),
		slog.Uint64("major", serverMajorVersion))

	switch {
	case serverMajorVersion < 8:
		return nil, errors.Errorf("unsupported elasticsearch version: %s. Minimum supported version is 8.x.x", info.Version.Number)
	case serverMajorVersion == 8:
		logger.Debug("using v8 client for v8 elasticsearch server...")
		return &elasticsearchReporter{client: wrapper, conf: conf}, nil
	default:
		logger.Info("server is v9 or higher, using v9 client", slog.Uint64("major_version", serverMajorVersion))
		cfg := esv9.Config{
			APIKey:    conf.ElasticsearchAPIKey,
			Addresses: []string{conf.ElasticsearchURL},
		}
		client, err := esv9.NewClient(cfg)
		if err != nil {
			return nil, errors.Errorf("error creating v9 client: %w", err)
		}

		wrapper := &v9Client{client: client}
		if _, err := getServerInfo(logger, wrapper); err != nil {
			return nil, errors.Errorf("failed to verify connection to elasticsearch: %w", err)
		}
		return &elasticsearchReporter{client: wrapper, conf: conf}, nil
	}
}

// getServerInfo retrieves and validates server information
func getServerInfo(logger componentlogger.Logger, cluster clusterInfo) (*esInfo, error) {
	res, err := cluster.Info()
	if err != nil {
		resStr := ""
		if res != nil {
			resStr = res.String()
		}
		return nil, errors.Errorf("could not get cluster information as proof of connection, err: %w, raw response: %s", err, resStr)
	}
	defer res.Body().Close()

	if res.StatusCode() != http.StatusOK || res.IsError() {
		return nil, errors.Errorf("could not contact Elasticsearch, attempted to retrieve cluster info and got status code: %d as a result, body: %s", res.StatusCode(), res.String())
	}

	logger.Debug("received information from elasticsearch successfully")

	var info esInfo
	decoder := json.NewDecoder(res.Body())
	if err := decoder.Decode(&info); err != nil {
		return nil, errors.Errorf("could not decode elasticsearch cluster information %w", err)
	}

	return &info, nil
}
