package env

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

type (
	// Parseable represents the types the parser is capable of handling.
	// TODO: extend with slices if needed.
	Parseable interface {
		string | bool | int | uint | uint32 | int64 | uint64 | float64 | time.Duration | time.Time
	}

	// ParseOption is a means to customize parse options via variadic parameters.
	ParseOption func(o *parseOpts) error

	// Loader is an alias for a function that loads values from the env.
	// It mirrors the signature of os.Getenv.
	Loader func(key string) string

	parseOpts struct {
		envLoader      Loader
		defaultOnError bool
		timeLayout     string
	}
)

var (
	defaultEnvParseOptions = parseOpts{
		envLoader:      os.Getenv,
		defaultOnError: false,
		timeLayout:     time.RFC3339,
	}
)

// WithLoader allows overriding how env vars are loaded.
//
// Primarily used for testing.
func WithLoader(loader Loader) ParseOption {
	return func(o *parseOpts) error {
		if loader == nil {
			return errors.New("env loader function cannot be nil")
		}

		o.envLoader = loader
		return nil
	}
}

// WithDefaultOnError informs the parser that if an error is encountered during parsing, it should fallback to the default value.
func WithDefaultOnError(fallback bool) ParseOption {
	return func(o *parseOpts) error {
		o.defaultOnError = fallback
		return nil
	}
}

// GetOrDefault attempts to parse the environment variable provided. If it is empty or missing, the default value is used.
//
// If an error is encountered, depending on whether the `WithDefaultOnError` option is provided it will either
// fall back or return the error back to the client.
func GetOrDefault[T Parseable](envVar string, defaultVal T, opts ...ParseOption) (dest T, err error) {
	if envVar == "" {
		return dest, errors.New("environment variable cannot be blank")
	}

	defaultOpts := &defaultEnvParseOptions
	for _, opt := range opts {
		if err := opt(defaultOpts); err != nil {
			return dest, fmt.Errorf("option error: %w", err)
		}
	}

	envStr := defaultOpts.envLoader(envVar)
	if envStr == "" {
		if !defaultOpts.defaultOnError {
			return dest, fmt.Errorf("required environment variable '%s' not found", envVar)
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
	case uint32:
		var i uint64
		i, err = strconv.ParseUint(envStr, 10, 32)
		v = uint32(i)
	case uint64:
		v, err = strconv.ParseUint(envStr, 10, 64)
	case float64:
		v, err = strconv.ParseFloat(envStr, 64)
	case time.Duration:
		v, err = time.ParseDuration(envStr)
	case time.Time:
		v, err = time.Parse(defaultOpts.timeLayout, envStr)
	}
	if err != nil {
		if defaultOpts.defaultOnError {
			return defaultVal, nil
		}

		return dest, fmt.Errorf("failed to parse environment variable '%s' to '%T': %w", envVar, dest, err)
	}

	dest, ok := v.(T)
	if !ok {
		return dest, fmt.Errorf("failed to cast environment variable '%s' to '%T'", envVar, dest)
	}

	return dest, nil
}
