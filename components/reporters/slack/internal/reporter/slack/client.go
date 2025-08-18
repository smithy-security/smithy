package slack

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/go-errors/errors"
	"github.com/slack-go/slack"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"
)

type (
	client struct {
		client    *slack.Client
		channelID string
	}

	// Config allows to customise the client config.
	Config struct {
		SlackToken     string
		SlackChannelID string
		SlackDebug     bool

		BaseClient *http.Client
	}
)

func (c Config) validate() error {
	switch {
	case c.SlackToken == "":
		return errors.New("invalid empty auth token")
	case c.SlackChannelID == "":
		return errors.New("invalid empty channel id")
	}
	return nil
}

// NewClient returns a new discord client.
func NewClient(c Config) (client, error) {
	if err := c.validate(); err != nil {
		return client{}, errors.Errorf("invalid config: %w", err)
	}

	s := slack.New(c.SlackToken,
		slack.OptionDebug(c.SlackDebug),
		slack.OptionHTTPClient(c.BaseClient),
	)

	sclackClient := client{
		client:    s,
		channelID: c.SlackChannelID,
	}
	if err := sclackClient.validateConnectivity(context.Background()); err != nil {
		return client{}, errors.Errorf("can't connect to slack err: %w", err)
	}
	return sclackClient, nil
}

func (c client) validateConnectivity(ctx context.Context) error {
	logger := componentlogger.LoggerFromContext(ctx)
	logger.Debug("validating slack connectivity...")

	// Test API connectivity
	_, err := c.client.AuthTest()
	if err != nil {
		return errors.Errorf("failed to authenticate with Slack: %w", err)
	}

	// Verify channel access
	_, err = c.client.GetConversationInfo(&slack.GetConversationInfoInput{
		ChannelID: c.channelID,
	})
	if err != nil {
		return errors.Errorf("failed to access channel %s: %w", c.channelID, err)
	}

	logger.Debug("slack connectivity validation successful")
	return nil
}

// CreateThread creates a thread in a channel by sending a message.
func (c client) CreateThread(ctx context.Context, msg string) (string, error) {
	logger := componentlogger.LoggerFromContext(ctx)

	logger.Debug("sending thread header message to channel...")
	_, timestamp, err := c.client.PostMessage(
		c.channelID,
		slack.MsgOptionText(msg, false),
	)
	if err != nil {
		return "", errors.Errorf("failed to post thread header message: %w", err)
	}
	logger.Debug("successfully sent thread header message to channel...")

	logger.Debug("replying to self, starting thread...")

	// Create thread by replying to the message
	threadMsg := slack.MsgOptionTS(timestamp)
	_, threadTS, err := c.client.PostMessage(
		c.channelID,
		slack.MsgOptionText("Thread started for detailed findings", false),
		threadMsg,
	)
	if err != nil {
		return "", errors.Errorf("failed to create thread: %w", err)
	}
	logger.Debug(
		"successfully started thread!",
		slog.String("message_timestamp", timestamp),
		slog.String("thread_id", threadTS),
	)

	return threadTS, nil
}

// SendMessages sends a batch of messages to discord in a thread.
func (c client) SendMessages(ctx context.Context, threadID string, messages []string) error {
	var (
		errs   error
		logger = componentlogger.
			LoggerFromContext(ctx).
			With(slog.String("thread_id", threadID))
	)

	logger.Debug("preparing to send message...")
	for i, msg := range messages {
		_, _, err := c.client.PostMessage(
			c.channelID,
			slack.MsgOptionText(msg, false),
			slack.MsgOptionTS(threadID),
		)
		if err != nil {
			return errors.Errorf("failed to send vulnerability detail %d: %w", i+1, err)
		}
	}
	logger.Debug("successfully sent messages!")

	return errs
}
