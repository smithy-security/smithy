package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/env"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"
)

type (
	Conf struct {
		SlackWebhook string
	}

	slackLogger struct {
		Conf   *Conf
		Client *http.Client
	}

	SlackRequestBody struct {
		Text string `json:"text"`
	}
)

// NewSlackLogger returns a new slack logger.
func NewSlackLogger(c *Conf, client *http.Client) (*slackLogger, error) {
	if c == nil {
		return nil, errors.New("configuration is nil")
	}
	return &slackLogger{
		Conf:   c,
		Client: client,
	}, nil
}

// NewConf returns a new configuration build from environment lookup.
func NewConf(envLoader env.Loader) (*Conf, error) {
	var envOpts = make([]env.ParseOption, 0)
	if envLoader != nil {
		envOpts = append(envOpts, env.WithLoader(envLoader))
	}

	webhook, err := env.GetOrDefault(
		"SLACK_WEBHOOK",
		"",
		append(envOpts, env.WithDefaultOnError(false))...,
	)
	if err != nil {
		return nil, errors.Errorf("could not get env variable for SLACK_WEBHOOK: %w", err)
	}

	return &Conf{
		SlackWebhook: webhook,
	}, nil
}

// Report logs the findings summary in slack.
func (s slackLogger) Report(
	ctx context.Context,
	findings []*vf.VulnerabilityFinding,
) error {
	logger := componentlogger.
		LoggerFromContext(ctx).
		With(slog.Int("num_findings", len(findings)))

	if len(findings) == 0 {
		logger.Error("Received 0 scans, this is likely an error, skipping sending empty message")
		return nil
	}
	scanID := findings[0].Finding.FindingInfo.Uid
	numResults := s.countFindings(findings)
	startTime := findings[0].Finding.StartTime
	asTime := time.Unix(*startTime, 0).UTC()
	toDatetime := asTime.Format(time.RFC3339)
	newFindings := s.countNewFindings(findings)
	logger.Debug("reporting",
		slog.Int("new_findings", newFindings),
		slog.String("start_time", toDatetime),
		slog.Int("num_results", numResults))

	msg := fmt.Sprintf("Smithy scan %s, started at %s, completed with %d findings, out of which %d new", scanID, toDatetime, numResults, newFindings)
	return s.push(ctx, msg, s.Conf.SlackWebhook)
}

func (s slackLogger) push(ctx context.Context, b string, webhook string) error {

	var err error
	body, err := json.Marshal(SlackRequestBody{Text: b})
	if err != nil {
		return err
	}
	ctx, cancelFunc := context.WithTimeout(ctx, time.Duration(10*time.Second))
	defer cancelFunc()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")

	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("failed to submit to slack, status code: %d", resp.StatusCode)
	}

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return fmt.Errorf("could not read from resp: %w", err)
	}

	if strings.ToLower(buf.String()) != "ok" {
		return errors.Errorf("non-ok response returned from Slack, received:%s", buf.String())
	}
	slog.Debug("successfully sent overview to slack")
	return nil
}

func (s slackLogger) countNewFindings(findings []*vf.VulnerabilityFinding) int {
	count := 0
	for _, finding := range findings {
		duplicate := false
		for _, e := range finding.Finding.Enrichments {
			if e.Type != nil && ocsffindinginfo.Enrichment_EnrichmentType_value[*e.Type] == int32(ocsffindinginfo.Enrichment_ENRICHMENT_TYPE_DUPLICATION) {
				duplicate = true
			}
		}
		if !duplicate {
			count += 1
		}
	}
	return count
}

func (s slackLogger) countFindings(findings []*vf.VulnerabilityFinding) int {
	count := 0
	for _, finding := range findings {
		count += len(finding.Finding.Vulnerabilities)
	}
	return count
}
