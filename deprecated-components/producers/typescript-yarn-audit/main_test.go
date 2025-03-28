package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/smithy-security/smithy/deprecated-components/producers"
)

func TestEndToEndCLIWithJSON(t *testing.T) {
	err := producers.TestEndToEnd(t, "./examples/result.json", "./examples/result.pb")
	assert.NoError(t, err)
}
