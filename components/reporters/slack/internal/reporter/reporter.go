package reporter

import (
	"context"
	"log/slog"
	"net/url"
	"strconv"
	"text/template"

	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/env"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"

	"github.com/smithy-security/smithy/components/reporters/slack/internal/reporter/paginator"
	"github.com/smithy-security/smithy/components/reporters/slack/internal/reporter/slack"
)

type (
	Conf struct {
		SmithyInstanceName string
		SmithyInstanceID   string
		SmithyDashURL      *url.URL
		SlackClientConfig  slack.Config
	}

	// MessageSender abstract sending messages to the underlying chat.
	MessageSender interface {
		CreateThread(ctx context.Context, msg string) (string, error)
		SendMessages(ctx context.Context, threadID string, messages []string) error
	}

	slackReporter struct {
		conf   *Conf
		client MessageSender
	}
)

// NewSlackReporter returns a new slack reporter.
func NewSlackReporter(c *Conf, client MessageSender) (*slackReporter, error) {
	if c == nil {
		return nil, errors.New("configuration is nil")
	}

	if c.SlackClientConfig.Token == "" {
		return nil, errors.New("Slack token is required")
	}

	if c.SlackClientConfig.ChannelID == "" {
		return nil, errors.New("Slack channel ID is required")
	}

	return &slackReporter{
		conf:   c,
		client: client,
	}, nil
}

// NewConf returns a new configuration build from environment lookup.
func NewConf(envLoader env.Loader) (*Conf, error) {
	var envOpts = make([]env.ParseOption, 0)
	if envLoader != nil {
		envOpts = append(envOpts, env.WithLoader(envLoader))
	}

	token, err := env.GetOrDefault(
		"SLACK_TOKEN",
		"",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, errors.Errorf("could not get env variable for SLACK_TOKEN: %w", err)
	}

	channel, err := env.GetOrDefault(
		"SLACK_CHANNEL",
		"",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, errors.Errorf("could not get env variable for SLACK_CHANNEL: %w", err)
	}

	if token == "" || channel == "" {
		return nil, errors.New("both SLACK_TOKEN and SLACK_CHANNEL are required")
	}

	slackClientDebug, err := env.GetOrDefault(
		"SLACK_DEBUG",
		"false",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, errors.Errorf("could not get env variable for SLACK_DEBUG: %w", err)
	}
	slackDebug, err := strconv.ParseBool(slackClientDebug)
	if err != nil {
		return nil, errors.Errorf("SLACK_DEBUG must be a boolean value('true' or 'false'), it is '%s' instead: %w", slackClientDebug, err)
	}

	smithyInstanceName, err := env.GetOrDefault(
		"SMITHY_INSTANCE_NAME",
		"",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, errors.Errorf("could not get env variable for SMITHY_INSTANCE_NAME: %w", err)
	}

	instanceID, err := env.GetOrDefault("SMITHY_INSTANCE_ID", "")
	if err != nil {
		return nil, errors.Errorf("failed to get env var SMITHY_INSTANCE_ID: %w", err)
	}

	dURL, err := env.GetOrDefault("SMITHY_PUBLIC_URL", "", env.WithDefaultOnError(true))
	if err != nil {
		return nil, errors.Errorf("failed to get env var SMITHY_PUBLIC_URL: %w", err)
	}
	dashURL, err := url.Parse(dURL)
	if err != nil {
		return nil, errors.Errorf("failed to parse env var SMITHY_PUBLIC_URL: %w", err)
	}

	return &Conf{
		SlackClientConfig: slack.Config{
			Token:      token,
			ChannelID:  channel,
			Debug:      slackDebug,
			BaseClient: nil, // This will be set later in the main function with a retry client
		},
		SmithyInstanceName: smithyInstanceName,
		SmithyInstanceID:   instanceID,
		SmithyDashURL:      dashURL,
	}, nil
}

// Report logs the findings summary in slack and optionally creates a thread with detailed findings.
func (r slackReporter) Report(ctx context.Context, findings []*vf.VulnerabilityFinding) error {
	logger := componentlogger.
		LoggerFromContext(ctx).
		With(slog.Int("num_findings", len(findings)))

	if len(findings) == 0 {
		logger.Debug("no findings found, skipping...")
		return nil
	}

	// Create thread
	threadMsg, err := r.getThreadHeading(r.countMsgs(findings))
	if err != nil {
		return errors.Errorf("error getting thread message: %w", err)
	}
	threadID, err := r.client.CreateThread(ctx, threadMsg)
	if err != nil {
		return errors.Errorf("error creating thread: %w", err)
	}

	// Paginate
	chunks := paginator.StreamObjects(findings, 100)

	// Send messages
	for chunk := range chunks {
		msgs, err := r.getMsgs(chunk)
		if err != nil {
			return errors.Errorf("error getting messages: %w", err)
		}

		logger.Debug("thread created", slog.String("thread_id", threadID))
		if err := r.client.SendMessages(ctx, threadID, msgs); err != nil {
			return errors.Errorf("error sending messages: %w", err)
		}
	}
	logger.Info("reporting completed successfully", slog.String("thread_id", threadID))
	return nil
}

func (r slackReporter) countMsgs(findings []*vf.VulnerabilityFinding) int {
	var total int
	for _, finding := range findings {
		total += len(finding.Finding.GetVulnerabilities())
	}
	return total
}

func (r slackReporter) getMsgs(objectPairs []paginator.ObjectPair) ([]string, error) {
	tpl, err := template.New("issue").Parse(issueTpl)
	if err != nil {
		return nil, errors.Errorf("could not parse thread template: %w", err)
	}

	var msgs []string
	for _, pair := range objectPairs {
		data, err := NewIssueData(pair.Finding, r.conf)
		if err != nil {
			return nil, errors.Errorf("could not create issue data from finding: %w", err)
		}
		vulnData, err := data.EnrichWithNewVulnerability(pair.Vulnerability)
		if err != nil {
			return nil, errors.Errorf("could not create issue data from vulnerability: %w", err)
		}
		msg, err := vulnData.String(tpl)
		if err != nil {
			return nil, errors.Errorf("could not create issue message from template: %w", err)
		}
		msgs = append(msgs, msg)

	}

	return msgs, nil
}
