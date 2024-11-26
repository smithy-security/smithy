package component

import (
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/sdk/component/internal/uuid"
)

type (
	// parseableEnvTypes represents the types the parser is capable of handling.
	// TODO: extend with slices if needed.
	parseableEnvTypes interface {
		string | bool | int | uint | int64 | uint64 | float64 | time.Duration | time.Time | url.URL | uuid.UUID
	}

	// envLoader is an alias for a function that loads values from the env. It mirrors the signature of os.Getenv.
	envLoader func(key string) string

	envParseOpts struct {
		envLoader      envLoader
		defaultOnError bool
		timeLayout     string
		sensitive      bool
	}

	// envParseOption is a means to customize parse options via variadic parameters.
	envParseOption func(o *envParseOpts) error
)

var (
	defaultEnvParseOptions = envParseOpts{
		envLoader:      os.Getenv,
		defaultOnError: false,
		timeLayout:     time.RFC3339,
	}
)

// withEnvLoader allows overriding how env vars are loaded.
//
// Primarily used for testing.
func withEnvLoader(loader envLoader) envParseOption {
	return func(o *envParseOpts) error {
		if loader == nil {
			return errors.New("env loader function cannot be nil")
		}

		o.envLoader = loader
		return nil
	}
}

// withFallbackToDefaultOnError informs the parser that if an error is encountered during parsing, it should fallback to the default value.
func withFallbackToDefaultOnError(fallback bool) envParseOption {
	return func(o *envParseOpts) error {
		o.defaultOnError = fallback
		return nil
	}
}

// fromEnvOrDefault attempts to parse the environment variable provided. If it is empty or missing, the default value is used.
//
// If an error is encountered, depending on whether the `withFallbackToDefaultOnError` option is provided it will either
// fallback or return the error back to the client.
func fromEnvOrDefault[T parseableEnvTypes](envVar string, defaultVal T, opts ...envParseOption) (dest T, err error) {
	parseOpts := &defaultEnvParseOptions
	for _, opt := range opts {
		if err := opt(parseOpts); err != nil {
			return dest, errors.Errorf("option error: %w", err)
		}
	}

	envStr := parseOpts.envLoader(envVar)
	if envStr == "" {
		if !parseOpts.defaultOnError {
			return dest, errors.Errorf("required env variable '%s' not found", envVar)
		}
		return defaultVal, nil
	}

	var v any

	switch any(dest).(type) {
	case string:
		v = envStr
	case bool:
		v, err = strconv.ParseBool(envStr)
	case int:
		v, err = strconv.Atoi(envStr)
	case uint:
		var i uint64
		i, err = strconv.ParseUint(envStr, 10, 64)
		v = uint(i)
	case int64:
		v, err = strconv.ParseInt(envStr, 10, 64)
	case uint64:
		v, err = strconv.ParseUint(envStr, 10, 64)
	case float64:
		v, err = strconv.ParseFloat(envStr, 64)
	case time.Duration:
		v, err = time.ParseDuration(envStr)
	case time.Time:
		v, err = time.Parse(parseOpts.timeLayout, envStr)
	case url.URL:
		v, err = url.Parse(envStr)
	case uuid.UUID:
		v, err = uuid.Parse(envStr)
	}
	if err != nil {
		if parseOpts.defaultOnError {
			return defaultVal, nil
		}

		return dest, errors.Errorf("failed to parse env %s to %T: %v", envVar, dest, err)
	}

	dest, ok := v.(T)
	if !ok {
		return dest, errors.Errorf("failed to cast env %s to %T", envVar, dest)
	}

	return dest, nil
}
