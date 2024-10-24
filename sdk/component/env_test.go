package component_test

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/sdk/component"
)

func TestParsesParseable(t *testing.T) {
	var makeLoader = func(envs map[string]string) component.EnvLoader {
		return func(key string) string {
			return envs[key]
		}
	}

	t.Run("string", func(t *testing.T) {
		const defaultVal = "default"
		var (
			loader = makeLoader(map[string]string{"KNOWN_STRING": "a string"})
			cases  = []struct {
				searchEnv     string
				expected      string
				fallBackOnErr bool
			}{
				{searchEnv: "KNOWN_STRING", expected: "a string", fallBackOnErr: true},
				{searchEnv: "UNKNOWN_ENV", expected: defaultVal, fallBackOnErr: true},
			}
		)
		for _, tt := range cases {
			t.Run(fmt.Sprintf("with env var %s", tt.searchEnv), func(t *testing.T) {
				ret, err := component.FromEnvOrDefault(
					tt.searchEnv,
					defaultVal,
					component.WithEnvLoader(loader),
					component.WithFallbackToDefaultOnError(tt.fallBackOnErr),
				)
				if err != nil {
					require.NoError(t, err)
				}
				require.Equal(t, tt.expected, ret)
			})
		}
	})

	t.Run("bool", func(t *testing.T) {
		const defaultVal = false
		var (
			loader = makeLoader(map[string]string{"KNOWN_BOOL": "true", "NOT_BOOL": "abcd"})
			cases  = []struct {
				searchEnv           string
				expected            bool
				expectedErrContains string
				fallBackOnErr       bool
			}{
				{searchEnv: "KNOWN_BOOL", expected: true, fallBackOnErr: true},
				{searchEnv: "UNKNOWN_ENV", expected: defaultVal, fallBackOnErr: true},
				{searchEnv: "NOT_BOOL", expected: false, expectedErrContains: "invalid syntax", fallBackOnErr: true},
			}
		)
		for _, tt := range cases {
			t.Run(fmt.Sprintf("with env var %s", tt.searchEnv), func(t *testing.T) {
				ret, err := component.FromEnvOrDefault(
					tt.searchEnv,
					defaultVal,
					component.WithEnvLoader(loader),
					component.WithFallbackToDefaultOnError(tt.fallBackOnErr),
				)
				if err != nil && tt.expectedErrContains != "" {
					require.True(t, strings.Contains(err.Error(), tt.expectedErrContains))
					return
				}

				require.NoError(t, err)
				require.Equal(t, tt.expected, ret)
			})
		}
	})

	t.Run("int", func(t *testing.T) {
		var defaultVal = rand.Int()
		var (
			loader = makeLoader(map[string]string{"KNOWN_INT": "123", "NOT_INT": "abcd"})
			cases  = []struct {
				searchEnv           string
				expected            int
				expectedErrContains string
				fallBackOnErr       bool
			}{
				{searchEnv: "KNOWN_INT", expected: 123, fallBackOnErr: true},
				{searchEnv: "UNKNOWN_ENV", expected: defaultVal, fallBackOnErr: true},
				{searchEnv: "NOT_INT", expectedErrContains: "invalid syntax", fallBackOnErr: false},
			}
		)
		for _, tt := range cases {
			t.Run(fmt.Sprintf("with env var %s", tt.searchEnv), func(t *testing.T) {
				ret, err := component.FromEnvOrDefault(
					tt.searchEnv,
					defaultVal,
					component.WithEnvLoader(loader),
					component.WithFallbackToDefaultOnError(tt.fallBackOnErr),
				)
				if err != nil && tt.expectedErrContains != "" {
					require.True(t, strings.Contains(err.Error(), tt.expectedErrContains))
					return
				}

				require.NoError(t, err)
				require.Equal(t, tt.expected, ret)
			})
		}
	})

	t.Run("uint", func(t *testing.T) {
		const defaultVal = uint(555)
		var (
			loader = makeLoader(map[string]string{"KNOWN_UINT": "123", "NOT_UINT": "abcd"})
			cases  = []struct {
				searchEnv           string
				expected            uint
				expectedErrContains string
				fallBackOnErr       bool
			}{
				{searchEnv: "KNOWN_UINT", expected: 123, fallBackOnErr: true},
				{searchEnv: "UNKNOWN_ENV", expected: defaultVal, fallBackOnErr: true},
				{searchEnv: "NOT_UINT", expectedErrContains: "invalid syntax", fallBackOnErr: false},
			}
		)
		for _, tt := range cases {
			t.Run(fmt.Sprintf("with env var %s", tt.searchEnv), func(t *testing.T) {
				ret, err := component.FromEnvOrDefault(
					tt.searchEnv,
					defaultVal,
					component.WithEnvLoader(loader),
					component.WithFallbackToDefaultOnError(tt.fallBackOnErr),
				)
				if err != nil && tt.expectedErrContains != "" {
					require.True(t, strings.Contains(err.Error(), tt.expectedErrContains))
					return
				}

				require.NoError(t, err)
				require.Equal(t, tt.expected, ret)
			})
		}
	})

	t.Run("int64", func(t *testing.T) {
		var (
			defaultVal = rand.Int63()
			loader     = makeLoader(map[string]string{"KNOWN_INT": "8675309", "NOT_INT": "abcd"})
			cases      = []struct {
				searchEnv           string
				expected            int64
				expectedErrContains string
				fallBackOnErr       bool
			}{
				{searchEnv: "KNOWN_INT", expected: 8675309, fallBackOnErr: true},
				{searchEnv: "UNKNOWN_ENV", expected: defaultVal, fallBackOnErr: true},
				{searchEnv: "NOT_INT", expectedErrContains: "invalid syntax", fallBackOnErr: false},
			}
		)
		for _, tt := range cases {
			t.Run(fmt.Sprintf("with env var %s", tt.searchEnv), func(t *testing.T) {
				ret, err := component.FromEnvOrDefault(
					tt.searchEnv,
					defaultVal,
					component.WithEnvLoader(loader),
					component.WithFallbackToDefaultOnError(tt.fallBackOnErr),
				)
				if err != nil && tt.expectedErrContains != "" {
					require.True(t, strings.Contains(err.Error(), tt.expectedErrContains))
					return
				}

				require.NoError(t, err)
				require.Equal(t, tt.expected, ret)
			})
		}
	})

	t.Run("uint64", func(t *testing.T) {
		var (
			defaultVal = rand.Uint64()
			loader     = makeLoader(map[string]string{"KNOWN_UINT": "5555555", "NOT_UINT": "abcd"})
			cases      = []struct {
				searchEnv           string
				expected            uint64
				expectedErrContains string
				fallBackOnErr       bool
			}{
				{searchEnv: "KNOWN_UINT", expected: 5555555, fallBackOnErr: true},
				{searchEnv: "UNKNOWN_ENV", expected: defaultVal, fallBackOnErr: true},
				{searchEnv: "NOT_UINT", expectedErrContains: "invalid syntax", fallBackOnErr: false},
			}
		)
		for _, tt := range cases {
			t.Run(fmt.Sprintf("with env var %s", tt.searchEnv), func(t *testing.T) {
				ret, err := component.FromEnvOrDefault(
					tt.searchEnv,
					defaultVal,
					component.WithEnvLoader(loader),
					component.WithFallbackToDefaultOnError(tt.fallBackOnErr),
				)
				if err != nil && tt.expectedErrContains != "" {
					require.True(t, strings.Contains(err.Error(), tt.expectedErrContains))
					return
				}

				require.NoError(t, err)
				require.Equal(t, tt.expected, ret)
			})
		}
	})

	t.Run("float64", func(t *testing.T) {
		var (
			defaultVal = rand.Float64()
			loader     = makeLoader(map[string]string{"KNOWN_FLOAT": "69.69", "NOT_FLOAT": "abcd"})
			cases      = []struct {
				searchEnv           string
				expected            float64
				expectedErrContains string
				fallBackOnErr       bool
			}{
				{searchEnv: "KNOWN_FLOAT", expected: 69.69, fallBackOnErr: true},
				{searchEnv: "UNKNOWN_ENV", expected: defaultVal, fallBackOnErr: true},
				{searchEnv: "NOT_FLOAT", expectedErrContains: "invalid syntax", fallBackOnErr: false},
			}
		)
		for _, tt := range cases {
			t.Run(fmt.Sprintf("with env var %s", tt.searchEnv), func(t *testing.T) {
				ret, err := component.FromEnvOrDefault(
					tt.searchEnv,
					defaultVal,
					component.WithEnvLoader(loader),
					component.WithFallbackToDefaultOnError(tt.fallBackOnErr),
				)
				if err != nil && tt.expectedErrContains != "" {
					require.True(t, strings.Contains(err.Error(), tt.expectedErrContains))
					return
				}

				require.NoError(t, err)
				require.Equal(t, tt.expected, ret)
			})
		}
	})

	t.Run("time.Duration", func(t *testing.T) {
		var (
			defaultVal = time.Minute * 5
			loader     = makeLoader(map[string]string{"KNOWN_DURATION": "10s", "NOT_DURATION": "abcd"})
			cases      = []struct {
				searchEnv           string
				expected            time.Duration
				expectedErrContains string
				fallBackOnErr       bool
			}{
				{searchEnv: "KNOWN_DURATION", expected: time.Second * 10, fallBackOnErr: true},
				{searchEnv: "UNKNOWN_ENV", expected: defaultVal, fallBackOnErr: true},
				{searchEnv: "NOT_DURATION", expectedErrContains: "invalid duration", fallBackOnErr: false},
			}
		)
		for _, tt := range cases {
			t.Run(fmt.Sprintf("with env var %s", tt.searchEnv), func(t *testing.T) {
				ret, err := component.FromEnvOrDefault(
					tt.searchEnv,
					defaultVal,
					component.WithEnvLoader(loader),
					component.WithFallbackToDefaultOnError(tt.fallBackOnErr),
				)
				if err != nil && tt.expectedErrContains != "" {
					require.True(t, strings.Contains(err.Error(), tt.expectedErrContains))
					return
				}

				require.NoError(t, err)
				require.Equal(t, tt.expected, ret)
			})
		}
	})

	t.Run("time.Time", func(t *testing.T) {
		var (
			defaultVal = time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)
			loader     = makeLoader(map[string]string{"KNOWN_TIME": "2021-01-01T00:00:00Z", "NOT_TIME": "abcd"})
			cases      = []struct {
				searchEnv           string
				expected            time.Time
				expectedErrContains string
				fallBackOnErr       bool
			}{
				{searchEnv: "KNOWN_TIME", expected: time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC), fallBackOnErr: true},
				{searchEnv: "UNKNOWN_ENV", expected: defaultVal, fallBackOnErr: true},
				{searchEnv: "NOT_TIME", expectedErrContains: "parsing time", fallBackOnErr: false},
			}
		)
		for _, tt := range cases {
			t.Run(fmt.Sprintf("with env var %s", tt.searchEnv), func(t *testing.T) {
				ret, err := component.FromEnvOrDefault(
					tt.searchEnv,
					defaultVal,
					component.WithEnvLoader(loader),
					component.WithFallbackToDefaultOnError(tt.fallBackOnErr),
				)
				if err != nil {
					require.Error(t, err)
					if tt.expectedErrContains != "" {
						require.True(t, strings.Contains(err.Error(), tt.expectedErrContains))
					}
					return
				}

				require.NoError(t, err)
				require.Equal(t, tt.expected, ret)
			})
		}
	})
}
