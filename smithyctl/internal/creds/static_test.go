package creds

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStaticCredsStore(t *testing.T) {
	testCases := []struct {
		name, host, username, password string
		errExpected                    bool
	}{
		{
			name:        "no host causes error",
			host:        "",
			username:    "foo",
			password:    "bar",
			errExpected: true,
		},
		{
			name:        "no username causes an error",
			host:        "localhost:5000",
			username:    "",
			password:    "bar",
			errExpected: true,
		},
		{
			name:        "no password causes an error",
			host:        "localhost:5000",
			username:    "foo",
			password:    "",
			errExpected: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ss, err := NewStaticStore(tt.host, tt.username, tt.password)
			if tt.errExpected {
				require.Error(t, err)
			} else {
				require.NotNil(t, ss)
			}
		})
	}
}
