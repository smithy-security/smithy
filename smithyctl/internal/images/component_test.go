package images

import (
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1 "github.com/smithy-security/smithy/pkg/types/v1"
)

func TestComponentDirectory(t *testing.T) {
	cr, _, err := ParseComponentRepository("scanners/some-component/component.yaml", "scanners/some-component")
	require.NoError(t, err)
	assert.Equal(t, path.Join(DefaultNamespace, "scanners/some-component"), cr.Repo())
	assert.Equal(t, v1.ComponentTypeScanner, cr.Type())
	assert.Equal(t, "some-component", cr.Name())
	assert.Equal(t, DefaultTag, cr.Tag())
	assert.Equal(t, "scanners/some-component", cr.Directory())
	assert.Equal(t, DefaultRegistry, cr.Registry())
	assert.Equal(t, path.Join(DefaultRegistry, DefaultNamespace, "scanners/some-component:latest"), cr.URL())

	cr, _, err = ParseComponentRepository("new-components/scanners/some-component/component.yaml", "new-components/scanners/some-component")
	require.NoError(t, err)
	assert.Equal(t, path.Join(DefaultNamespace, "new-components/scanners/some-component"), cr.Repo())
	assert.Equal(t, v1.ComponentTypeScanner, cr.Type())
	assert.Equal(t, "some-component", cr.Name())
	assert.Equal(t, DefaultTag, cr.Tag())
	assert.Equal(t, "new-components/scanners/some-component", cr.Directory())
	assert.Equal(t, DefaultRegistry, cr.Registry())
	assert.Equal(t, path.Join(DefaultRegistry, DefaultNamespace, "new-components/scanners/some-component:latest"), cr.URL())

	cr, parsedRef, err := ParseComponentRepository("new-components/scanners/some-component/component.yaml", "gosec:2.22.2")
	require.ErrorIs(t, err, ErrNotAComponentRepo)
	require.Nil(t, cr)
	assert.Equal(t, "gosec", parsedRef.Repository.RepositoryStr())
	assert.Equal(t, "2.22.2", parsedRef.TagStr())

	cr, parsedRef, err = ParseComponentRepository("new-components/scanners/some-component/component.yaml", "components/scanners/some-component")
	require.ErrorIs(t, err, ErrNotAComponentRepo)
	require.Nil(t, cr)
	assert.Equal(t, "components/scanners/some-component", parsedRef.Repository.RepositoryStr())

	cr, _, err = ParseComponentRepository(
		"new-components/scanners/some-component/component.yaml",
		"new-components/scanners/some-component",
		WithNamespace("some/namespace"),
		WithRegistry("kind-registry:5000"),
		WithDefaultTag("1.0.0-dev"),
	)
	require.NoError(t, err)
	assert.Equal(t, path.Join("some/namespace", "new-components/scanners/some-component"), cr.Repo())
	assert.Equal(t, v1.ComponentTypeScanner, cr.Type())
	assert.Equal(t, "some-component", cr.Name())
	assert.Equal(t, "1.0.0-dev", cr.Tag())
	assert.Equal(t, "new-components/scanners/some-component", cr.Directory())
	assert.Equal(t, "kind-registry:5000", cr.Registry())
	assert.Equal(t, path.Join("kind-registry:5000", "some/namespace", "new-components/scanners/some-component:1.0.0-dev"), cr.URL())

	cr, _, err = ParseComponentRepository(
		"new-components/scanners/some-component/component.yaml",
		"new-components/scanners/some-component",
		WithNamespace("some/namespace"),
		WithRegistry("kind-registry:5000"),
		WithDefaultTag("1.0.0-dev"),
		WithExtraTags("latest", "1.0.0-amd64"),
	)
	require.NoError(t, err)
	assert.Equal(t, path.Join("some/namespace", "new-components/scanners/some-component"), cr.Repo())
	assert.Equal(t, v1.ComponentTypeScanner, cr.Type())
	assert.Equal(t, "some-component", cr.Name())
	assert.Equal(t, "1.0.0-dev", cr.Tag())
	assert.Equal(t, "new-components/scanners/some-component", cr.Directory())
	assert.Equal(t, "kind-registry:5000", cr.Registry())
	assert.Equal(t, path.Join("kind-registry:5000", "some/namespace", "new-components/scanners/some-component:1.0.0-dev"), cr.URL())
	assert.ElementsMatch(t,
		[]string{
			path.Join("kind-registry:5000", "some/namespace", "new-components/scanners/some-component:1.0.0-dev"),
			path.Join("kind-registry:5000", "some/namespace", "new-components/scanners/some-component:1.0.0-amd64"),
			path.Join("kind-registry:5000", "some/namespace", "new-components/scanners/some-component:latest"),
		},
		cr.URLs(),
	)
}
