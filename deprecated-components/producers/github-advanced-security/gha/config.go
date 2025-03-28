package gha

import (
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-errors/errors"

	v1proto "github.com/smithy-security/smithy/api/proto/v1"
)

var (
	// ErrNoRepositoryOwner is returned when the client config has no
	// repository owner
	ErrNoRepositoryOwner = errors.New("no repository owner provided")
	// ErrNoRepositoryName is returned when the client config has no
	// repository name
	ErrNoRepositoryName = errors.New("no repository name provided")
	// ErrNoRef is returned when the client config has no branch ref
	ErrNoRef = errors.New("no branch ref provided")
	// ErrClientPageSizeTooLarge is returned when the page list is larger than
	// 100
	ErrClientPageSizeTooLarge = errors.New("client page size maximum can be 100")
	// ErrWrongSeverity is returned when the severity level can't be parsed
	ErrWrongSeverity = errors.New("wrong severity value")
	// ErrNoOauth2TokenProvided is returned when no oauth2 token is provided
	ErrNoOauth2TokenProvided = errors.New("no oauth2 token provided")
	// ErrWrongRequestTimeoutDuration is returned when the request duration
	// can't be parsed
	ErrWrongRequestTimeoutDuration = errors.New("wrong request duration")
	// ErrCouldNotParsePageSize is returned when there is no
	ErrCouldNotParsePageSize = errors.New("could not parse page size")
)

// ClientConfig is used to gather all the importat
type ClientConfig struct {
	// RepositoryOwner is the owner of the GitHub repository
	RepositoryOwner string

	// RepositoryName is the name of the GitHub repository
	RepositoryName string

	// Token is the GitHub token used to authenticate
	Token string

	// Toolname is the name of tool to fetch results for
	Toolname string

	// Ref is the reference of the branch or the pull request to use. It should
	// be either of the form `refs/heads/<branch name>`, branch name or
	// `refs/pulls/<pull request id>`
	Ref string

	// Severity if specified, causes only code scanning alerts with this
	// severity will be returned. Possible values are: critical, high, medium,
	// low, warning, note, error
	Severity string

	// RequestTimeout is how long to wait for github to respond
	RequestTimeoutStr string

	// RequestTimeout is the parsed max duration of each request. Max is 5m
	// default is 30s
	RequestTimeout time.Duration

	// PageSizeStr defines how many alerts to ask from github at once
	PageSizeStr string

	// PageSize is the maximum number of results to request from the API per
	// request. If PageSizeStr is set, it will be converted into an integer and
	// override this value. Max value is 100
	PageSize int
}

func (c *ClientConfig) Parse() error {
	if c.RepositoryOwner == "" {
		return ErrNoRepositoryOwner
	}

	if c.RepositoryName == "" {
		return ErrNoRepositoryName
	}

	if c.Token == "" {
		return ErrNoOauth2TokenProvided
	}

	if c.Ref == "" {
		return ErrNoRef
	}

	if c.Severity != "" {
		possibleValues := map[string]struct{}{
			"critical": {},
			"high":     {},
			"medium":   {},
			"low":      {},
			"warning":  {},
			"note":     {},
			"error":    {},
		}
		if _, correct := possibleValues[c.Severity]; !correct {
			return errors.Errorf("%w: %s: possible values are: %s",
				ErrWrongSeverity, c.Severity,
				strings.Join(slices.Collect(maps.Keys(v1proto.Severity_value)), ","),
			)
		}
	}

	if c.RequestTimeoutStr != "" {
		var err error
		c.RequestTimeout, err = time.ParseDuration(c.RequestTimeoutStr)
		if err != nil {
			return errors.Errorf("%w: %w: %s", ErrWrongRequestTimeoutDuration, err, c.RequestTimeoutStr)
		}
	} else {
		if c.RequestTimeout > 5*time.Minute {
			return errors.Errorf("%w: request duration greater than 5 minutes", ErrWrongRequestTimeoutDuration)
		}
	}

	if c.PageSizeStr != "" {
		var err error
		c.PageSize, err = strconv.Atoi(c.PageSizeStr)
		if err != nil {
			return errors.Errorf("%w: %s", ErrCouldNotParsePageSize, c.PageSizeStr)
		}
	} else {
		c.PageSize = 100
	}

	return nil
}
