package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHandleSemgrepCWE(t *testing.T) {
	testcases := []struct {
		name      string
		input     string
		expected  int32
		expectErr error
	}{
		{
			name:      "valid CWE",
			input:     "CWE-123: Test",
			expected:  123,
			expectErr: nil,
		},
		{
			name:      "invalid CWE format",
			input:     "CWE-",
			expected:  0,
			expectErr: ErrCWEInvalidNumber,
		},
		{
			name:      "invalid CWE",
			input:     "123",
			expected:  0,
			expectErr: ErrCWEMissingPrefix,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			cwe, err := extractCWENumber(tc.input)
			require.ErrorIs(t, err, tc.expectErr)
			require.Equal(t, tc.expected, cwe)
		})
	}
}
