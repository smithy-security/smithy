package reporter

import (
	"context"
	"log/slog"
	"net/url"
	"strconv"

	"github.com/go-errors/errors"
	"github.com/smithy-security/pkg/env"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"

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

	if c.SlackClientConfig.SlackToken == "" {
		return nil, errors.New("Slack token is required")
	}

	if c.SlackClientConfig.SlackChannelID == "" {
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
			SlackToken:     token,
			SlackChannelID: channel,
			SlackDebug:     slackDebug,
			BaseClient:     nil, // This will be set later in the main function with a retry client
		},
		SmithyInstanceName: smithyInstanceName,
		SmithyInstanceID:   instanceID,
		SmithyDashURL:      dashURL,
	}, nil
}

// Report logs the findings summary in slack and optionally creates a thread with detailed findings.
func (r slackReporter) Report(
	ctx context.Context,
	findings []*vf.VulnerabilityFinding,
) error {
	logger := componentlogger.
		LoggerFromContext(ctx).
		With(slog.Int("num_findings", len(findings)))

	if len(findings) == 0 {
		logger.Debug("no findings found, skipping...")
		return nil
	}
	msgs, err := r.getMsgs(findings)
	if err != nil {
		return errors.Errorf("error getting messages: %w", err)
	}

	threadMsg, err := r.getThreadHeading(len(msgs))
	if err != nil {
		return errors.Errorf("error getting thread message: %w", err)
	}
	threadID, err := r.client.CreateThread(ctx, threadMsg)
	if err != nil {
		return errors.Errorf("error creating thread: %w", err)
	}
	logger.Debug("thread created", slog.String("thread_id", threadID))
	return r.client.SendMessages(ctx, threadID, msgs)
}
