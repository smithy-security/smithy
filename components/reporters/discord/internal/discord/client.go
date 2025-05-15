package discord

import (
	"context"
	"net/http"

	"github.com/bwmarrin/discordgo"
	"github.com/go-errors/errors"
)

type (
	client struct {
		sess      *discordgo.Session
		channelID string
	}

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

func NewClient(c Config) (client, error) {
	if err := c.validate(); err != nil {
		return client{}, errors.Errorf("invalid config: %w", err)
	}

	s, err := discordgo.New(c.AuthToken)
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

func (c client) CreateThread(ctx context.Context, msg string) (string, error) {
	firstMsg, err := c.sess.ChannelMessageSend(c.channelID, msg)
	if err != nil {
		return "", errors.Errorf("could not send message: %w", err)
	}

	thread, err := c.sess.MessageThreadStartComplex(c.channelID, firstMsg.ID, &discordgo.ThreadStart{
		Name: msg,
	})
	if err != nil {
		return "", errors.Errorf("could not create thread for message '%s': %w", firstMsg.ID, err)
	}

	return thread.ID, nil
}

func (c client) SendMessages(ctx context.Context, threadID string, messages []string) error {
	var errs error

	for _, msg := range messages {
		if _, err := c.sess.ChannelMessageSend(threadID, msg); err != nil {
			errs = errors.Join(errs, err)
		}
	}

	return errs
}

func (c client) Close() error {
	return c.sess.Close()
}
