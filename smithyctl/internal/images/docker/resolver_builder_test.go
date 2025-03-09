package docker

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDynamicBuild(t *testing.T) {
	dynamicBuilder, err := NewResolverBuilder(nil)
	require.NoError(t, err)

	testCtx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	require.NoError(t, dynamicBuilder.Resolve(testCtx, "docker.io/securego/gosec:2.15.0"))
	require.NoError(t, dynamicBuilder.Resolve(testCtx, "new-components/targets/git-clone"))
}
