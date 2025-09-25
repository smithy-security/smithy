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
		client *slack.Client
		config Config
	}

	// Config allows to customise the client config.
	Config struct {
		Token     string
		ChannelID string
		Debug     bool

		BaseClient *http.Client
	}
)

func (c Config) validate() error {
	switch {
	case c.Token == "":
		return errors.New("invalid empty auth token")
	case c.ChannelID == "":
		return errors.New("invalid empty channel id")
	}
	return nil
}

// NewClient returns a new discord client.
func NewClient(ctx context.Context, c Config) (client, error) {
	if err := c.validate(); err != nil {
		return client{}, errors.Errorf("invalid config: %w", err)
	}

	s := slack.New(c.Token,
		slack.OptionDebug(c.Debug),
		slack.OptionHTTPClient(c.BaseClient),
	)

	slackClient := client{
		client: s,
		config: c,
	}

	if err := slackClient.validateConnectivity(ctx); err != nil {
		return client{}, errors.Errorf("can't connect to slack err: %w", err)
	}

	return slackClient, nil
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
		ChannelID: c.config.ChannelID,
	})
	if err != nil {
		return errors.Errorf("failed to access channel %s: %w", c.config.ChannelID, err)
	}

	logger.Debug("slack connectivity validation successful")
	return nil
}

// CreateThread creates a thread in a channel by sending a message.
func (c client) CreateThread(ctx context.Context, msg string) (string, error) {
	logger := componentlogger.LoggerFromContext(ctx)

	logger.Debug("sending thread header message to channel...")
	_, timestamp, err := c.client.PostMessage(
		c.config.ChannelID,
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
		c.config.ChannelID,
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

	if threadID == "" {
		return errors.New("invalid empty thread id")
	}

	if len(messages) == 0 {
		return nil
	}

	logger.Debug("preparing to send message...")
	for _, msg := range messages {
		_, _, err := c.client.PostMessage(
			c.config.ChannelID,
			slack.MsgOptionText(msg, false),
			slack.MsgOptionTS(threadID),
		)
		if err != nil {
			errs = errors.Wrap(errors.Errorf("%w\nfailed to send vulnerability detail '%s': %w", errs, msg, err), 0)
		}
	}
	logger.Debug("successfully sent messages!")

	return errs
}
