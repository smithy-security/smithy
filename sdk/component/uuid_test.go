package component_test

import (
	"testing"

	googleuuid "github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smithy-security/smithy/sdk/component"
)

func TestUUID(t *testing.T) {
	for _, tt := range []struct {
		testCase   string
		idStr      string
		expectedID component.UUID
		expectsErr bool
	}{
		{
			testCase:   "it should return a nil uuid when an empty string is supplied",
			idStr:      "",
			expectedID: component.Nil,
			expectsErr: false,
		},
		{
			testCase:   "it should return an error when an invalid string is supplied",
			idStr:      "rust>go",
			expectedID: component.Nil,
			expectsErr: true,
		},
		{
			testCase:   "it should correctly parse a UUID",
			idStr:      "20ef2e2d-211f-4e08-afdf-f0055f0e416a",
			expectedID: component.UUID(googleuuid.MustParse("20ef2e2d-211f-4e08-afdf-f0055f0e416a")),
			expectsErr: false,
		},
	} {
		t.Run(tt.testCase, func(t *testing.T) {
			id, err := component.ParseUUID(tt.idStr)
			if tt.expectsErr {
				require.Error(t, err)
				assert.Equal(t, component.Nil, id)
				assert.True(t, id.IsNil())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expectedID, id)
			assert.Equal(t, tt.expectedID.String(), id.String())
			if tt.idStr != "" {
				assert.False(t, id.IsNil())
			} else {
				assert.True(t, id.IsNil())
			}
		})
	}
}
