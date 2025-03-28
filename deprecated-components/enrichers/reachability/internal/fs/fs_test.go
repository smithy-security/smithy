package fs_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/smithy-security/smithy/deprecated-components/enrichers/reachability/internal/fs"
)

func TestNewReadWriter(t *testing.T) {
	const (
		readPath  = "/some/read/path"
		writePath = "/some/write/path"
	)

	for _, tt := range []struct {
		testCase   string
		readPath   string
		writePath  string
		expectsErr bool
	}{
		{
			testCase:   "it returns an error because the supplied read path is empty",
			readPath:   "",
			writePath:  writePath,
			expectsErr: true,
		},
		{
			testCase:   "it returns an error because the supplied write path is empty",
			readPath:   readPath,
			writePath:  "",
			expectsErr: true,
		},
		{
			testCase:   "it returns a new reader",
			readPath:   readPath,
			writePath:  writePath,
			expectsErr: false,
		},
	} {
		t.Run(tt.testCase, func(t *testing.T) {
			t.Parallel()

			rw, err := fs.NewReadWriter(tt.readPath, tt.writePath)
			if tt.expectsErr {
				assert.Error(t, err)
				assert.Nil(t, rw)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, rw)
			}
		})
	}
}
