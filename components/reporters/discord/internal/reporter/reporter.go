package reporter

import (
	"context"

	"github.com/go-errors/errors"
	"github.com/smithy-security/smithy/sdk/component"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"

	"github.com/smithy-security/smithy/components/reporters/discord/internal/config"
)

type (
	// MessageSender abstract sending messages to the underlying chat.
	MessageSender interface {
		CreateThread(ctx context.Context, msg string) (string, error)
		SendMessages(ctx context.Context, threadID string, messages []string) error
		Close() error
	}
	reporter struct {
		ms  MessageSender
		cfg config.Config
	}
)

// New returns a new reporter.
func New(cfg config.Config, ms MessageSender) (*reporter, error) {
	if ms == nil {
		return nil, errors.New("message sender must not be nil")
	}
	return &reporter{cfg: cfg, ms: ms}, nil
}

// Report reports issues found to the implemented messages platform.
func (r reporter) Report(ctx context.Context, findings []*vf.VulnerabilityFinding) error {
	logger := component.LoggerFromContext(ctx)
	if len(findings) == 0 {
		logger.Debug("no findings found, skipping...")
		return nil
	}

	logger.Debug("starting reporting thread...")
	threadMsg, err := r.getThreadMsg(len(findings))
	if err != nil {
		return errors.Errorf("error getting thread message: %w", err)
	}

	threadID, err := r.ms.CreateThread(ctx, threadMsg)
	if err != nil {
		return errors.Errorf("error creating thread: %w", err)
	}
	logger.Debug("successfully created thread!")

	logger.Debug("sending thread message to channel...")
	msgs, err := r.getMsgs(findings)
	if err != nil {
		return errors.Errorf("error getting messages: %w", err)
	}

	if err := r.ms.SendMessages(ctx, threadID, msgs); err != nil {
		return errors.Errorf("error sending messages: %w", err)
	}
	logger.Debug("successfully sent messages!")

	return r.ms.Close()
}
