package discord

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/bwmarrin/discordgo"
	"github.com/go-errors/errors"
	"github.com/smithy-security/smithy/sdk/component"
)

type (
	client struct {
		sess      *discordgo.Session
		channelID string
	}

	// Config allows to customise the client config.
	Config struct {
		AuthToken  string
		ChannelID  string
		BaseClient *http.Client
	}
)

func (c Config) validate() error {
	switch {
	case c.AuthToken == "":
		return errors.New("invalid empty auth token")
	case c.ChannelID == "":
		return errors.New("invalid empty channel id")
	}
	return nil
}

// NewClient returns a new discord client.
func NewClient(c Config) (client, error) {
	if err := c.validate(); err != nil {
		return client{}, errors.Errorf("invalid config: %w", err)
	}

	s, err := discordgo.New("Bot " + c.AuthToken)
	if err != nil {
		return client{}, errors.Errorf("could not create discord session: %w", err)
	}

	if c.BaseClient != nil {
		s.Client = c.BaseClient
	}

	return client{
		sess:      s,
		channelID: c.ChannelID,
	}, err
}

// CreateThread creates a thread in a channel by sending a message.
func (c client) CreateThread(ctx context.Context, msg string) (string, error) {
	logger := component.LoggerFromContext(ctx)

	logger.Debug("sending thread message to channel...")
	firstMsg, err := c.sess.ChannelMessageSend(c.channelID, msg)
	if err != nil {
		return "", errors.Errorf("could not send message: %w", err)
	}
	logger.Debug("successfully sent thread message message to channel...")

	logger.Debug("starting thread...", slog.String("message_id", firstMsg.ID))
	thread, err := c.sess.MessageThreadStartComplex(c.channelID, firstMsg.ID, &discordgo.ThreadStart{
		Name: msg,
	})
	if err != nil {
		return "", errors.Errorf("could not create thread for message '%s': %w", firstMsg.ID, err)
	}
	logger.Debug(
		"successfully started thread!",
		slog.String("message_id", firstMsg.ID),
		slog.String("thread_id", thread.ID),
	)

	return thread.ID, nil
}

// SendMessages sends a batch of messages to discord in a thread.
func (c client) SendMessages(ctx context.Context, threadID string, messages []string) error {
	var (
		errs   error
		logger = component.
			LoggerFromContext(ctx).
			With(slog.String("thread_id", threadID))
	)

	logger.Debug("preparing to send messages...")
	for _, msg := range messages {
		if _, err := c.sess.ChannelMessageSend(threadID, msg); err != nil {
			logger.Error(
				"could not send message",
				slog.String("message", msg),
				slog.String("err", err.Error()),
			)
			errs = errors.Join(errs, err)
		}
	}
	logger.Debug("successfully sent messages!")

	return errs
}

// Close closes the discord client.
func (c client) Close() error {
	return c.sess.Close()
}
