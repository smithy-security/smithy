package images

import (
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1 "github.com/smithy-security/smithy/pkg/types/v1"
)

type testURLProcessor struct{}

func (t *testURLProcessor) Process(repo string) string {
	return strings.Replace(repo, "/", "-", -1)
}

func TestComponentDirectory(t *testing.T) {
	t.Run("parse a Smithy component correctly", func(t *testing.T) {
		cr, _, err := ParseComponentRepository("scanners/some-component/component.yaml", "scanners/some-component")
		require.NoError(t, err)
		assert.Equal(t, path.Join(DefaultNamespace, "scanners/some-component"), cr.Repo())
		assert.Equal(t, v1.ComponentTypeScanner, cr.Type())
		assert.Equal(t, "some-component", cr.Name())
		assert.ElementsMatch(t, []string{"latest"}, cr.Tags())
		assert.Equal(t, "scanners/some-component", cr.Directory())
		assert.Equal(t, DefaultRegistry, cr.Registry())
		assert.ElementsMatch(
			t,
			[]string{path.Join(DefaultRegistry, DefaultNamespace, "scanners/some-component:latest")},
			cr.URLs(),
		)
	})

	t.Run("parse a smithy component inside a folder", func(t *testing.T) {
		cr, _, err := ParseComponentRepository("new-components/scanners/some-component/component.yaml", "new-components/scanners/some-component")
		require.NoError(t, err)
		assert.Equal(t, path.Join(DefaultNamespace, "new-components/scanners/some-component"), cr.Repo())
		assert.Equal(t, v1.ComponentTypeScanner, cr.Type())
		assert.Equal(t, "some-component", cr.Name())
		assert.ElementsMatch(t, []string{"latest"}, cr.Tags())
		assert.Equal(t, "new-components/scanners/some-component", cr.Directory())
		assert.Equal(t, DefaultRegistry, cr.Registry())
		assert.ElementsMatch(
			t,
			[]string{path.Join(DefaultRegistry, DefaultNamespace, "new-components/scanners/some-component:latest")},
			cr.URLs(),
		)
	})

	t.Run("parse an external image", func(t *testing.T) {
		cr, parsedRef, err := ParseComponentRepository("new-components/scanners/some-component/component.yaml", "gosec:2.22.2")
		require.NoError(t, err)
		require.Nil(t, cr)
		assert.Equal(t, "index.docker.io", parsedRef.RegistryStr())
		assert.Equal(t, "library/gosec", parsedRef.RepositoryStr())
		assert.Equal(t, "2.22.2", parsedRef.TagStr())
	})

	t.Run("parse an image reference that is not part of the component", func(t *testing.T) {
		cr, parsedRef, err := ParseComponentRepository("new-components/scanners/some-component/component.yaml", "components/scanners/some-component")
		require.NoError(t, err)
		require.Nil(t, cr)
		assert.Equal(t, "components/scanners/some-component", parsedRef.Repository.RepositoryStr())
	})

	t.Run("parse a component image with a custom registry", func(t *testing.T) {
		cr, _, err := ParseComponentRepository(
			"new-components/scanners/some-component/component.yaml",
			"new-components/scanners/some-component",
			WithNamespace("some/namespace"),
			WithRegistry("kind-registry:5000"),
			WithTags("1.0.0-dev"),
		)
		require.NoError(t, err)
		assert.Equal(t, path.Join("some/namespace", "new-components/scanners/some-component"), cr.Repo())
		assert.Equal(t, v1.ComponentTypeScanner, cr.Type())
		assert.Equal(t, "some-component", cr.Name())
		assert.ElementsMatch(t, []string{"1.0.0-dev"}, cr.Tags())
		assert.Equal(t, "new-components/scanners/some-component", cr.Directory())
		assert.Equal(t, "kind-registry:5000", cr.Registry())
		assert.ElementsMatch(
			t,
			[]string{path.Join("kind-registry:5000", "some/namespace", "new-components/scanners/some-component:1.0.0-dev")},
			cr.URLs(),
		)
	})

	t.Run("parse a component image with multiple tags", func(t *testing.T) {
		cr, _, err := ParseComponentRepository(
			"new-components/scanners/some-component/component.yaml",
			"new-components/scanners/some-component",
			WithNamespace("some/namespace"),
			WithRegistry("kind-registry:5000"),
			WithTags("1.0.0-dev", "latest", "1.0.0-amd64"),
		)
		require.NoError(t, err)
		assert.Equal(t, path.Join("some/namespace", "new-components/scanners/some-component"), cr.Repo())
		assert.Equal(t, v1.ComponentTypeScanner, cr.Type())
		assert.Equal(t, "some-component", cr.Name())
		assert.ElementsMatch(t, []string{"1.0.0-dev", "1.0.0-amd64", "latest"}, cr.Tags())
		assert.Equal(t, "new-components/scanners/some-component", cr.Directory())
		assert.Equal(t, "kind-registry:5000", cr.Registry())
		assert.ElementsMatch(t,
			[]string{
				path.Join("kind-registry:5000", "some/namespace", "new-components/scanners/some-component:1.0.0-dev"),
				path.Join("kind-registry:5000", "some/namespace", "new-components/scanners/some-component:1.0.0-amd64"),
				path.Join("kind-registry:5000", "some/namespace", "new-components/scanners/some-component:latest"),
			},
			cr.URLs(),
		)
	})

	t.Run("parse a component helper image with multiple tags", func(t *testing.T) {
		cr, _, err := ParseComponentRepository(
			"new-components/scanners/some-component/component.yaml",
			"new-components/scanners/some-component/helper",
			WithNamespace("some/namespace"),
			WithRegistry("kind-registry:5000"),
			WithTags("1.0.0-dev", "latest", "1.0.0-amd64"),
		)
		require.NoError(t, err)
		assert.Equal(t, path.Join("some/namespace", "new-components/scanners/some-component/helper"), cr.Repo())
		assert.Equal(t, v1.ComponentTypeScanner, cr.Type())
		assert.Equal(t, "some-component/helper", cr.Name())
		assert.ElementsMatch(t, []string{"1.0.0-dev", "1.0.0-amd64", "latest"}, cr.Tags())
		assert.Equal(t, "new-components/scanners/some-component/helper", cr.Directory())
		assert.Equal(t, "kind-registry:5000", cr.Registry())
		assert.ElementsMatch(t,
			[]string{
				path.Join("kind-registry:5000", "some/namespace", "new-components/scanners/some-component/helper:1.0.0-dev"),
				path.Join("kind-registry:5000", "some/namespace", "new-components/scanners/some-component/helper:1.0.0-amd64"),
				path.Join("kind-registry:5000", "some/namespace", "new-components/scanners/some-component/helper:latest"),
			},
			cr.URLs(),
		)
	})

	t.Run("parse a component image with an image URL processor", func(t *testing.T) {
		cr, _, err := ParseComponentRepository(
			"new-components/scanners/some-component/component.yaml",
			"new-components/scanners/some-component/helper",
			WithNamespace("some/namespace"),
			WithRegistry("kind-registry:5000"),
			WithTags("1.0.0-dev", "latest", "1.0.0-amd64"),
			WithImageProcessor(&testURLProcessor{}),
		)
		require.NoError(t, err)
		assert.Equal(t, "some-namespace-new-components-scanners-some-component-helper", cr.Repo())
		assert.Equal(t, v1.ComponentTypeScanner, cr.Type())
		assert.Equal(t, "some-component/helper", cr.Name())
		assert.ElementsMatch(t, []string{"1.0.0-dev", "1.0.0-amd64", "latest"}, cr.Tags())
		assert.Equal(t, "new-components/scanners/some-component/helper", cr.Directory())
		assert.Equal(t, "kind-registry:5000", cr.Registry())
		assert.ElementsMatch(t,
			[]string{
				path.Join("kind-registry:5000", "some-namespace-new-components-scanners-some-component-helper:1.0.0-dev"),
				path.Join("kind-registry:5000", "some-namespace-new-components-scanners-some-component-helper:1.0.0-amd64"),
				path.Join("kind-registry:5000", "some-namespace-new-components-scanners-some-component-helper:latest"),
			},
			cr.URLs(),
		)
	})

	t.Run("parse an external image with a replacement", func(t *testing.T) {
		cr, parsedRef, err := ParseComponentRepository(
			"new-components/scanners/some-component/component.yaml",
			"index.docker.io/library/gosec:2.22.2",
			WithImageReplacements(map[string]string{"index.docker.io/library/gosec:2.22.2": "index.docker.io/library/busybox:latest"}),
		)
		require.NoError(t, err)
		require.Nil(t, cr)
		assert.Equal(t, "library/busybox", parsedRef.Repository.RepositoryStr())
		assert.Equal(t, "latest", parsedRef.TagStr())
	})

	t.Run("parse a component image that is hard coded to a remote repository", func(t *testing.T) {
		cr, parsedRef, err := ParseComponentRepository(
			"new-components/scanners/some-component/component.yaml",
			"ghcr.io/smithy-security/new-components/scanners/some-component:2.22.2",
			WithImageReplacements(map[string]string{"index.docker.io/library/gosec:2.22.2": "index.docker.io/library/busybox:latest"}),
		)
		require.NoError(t, err)
		require.Nil(t, cr)
		assert.Equal(t, "smithy-security/new-components/scanners/some-component", parsedRef.Repository.RepositoryStr())
		assert.Equal(t, "2.22.2", parsedRef.TagStr())
	})
}

func TestRegex(t *testing.T) {
	assert.True(t, componentRepositoryRegex.MatchString("new-components/bla/scanners/gosec"))
	assert.True(t, componentRepositoryRegex.MatchString("components/scanners/component"))
	assert.True(t, componentRepositoryRegex.MatchString("scanners/bla"))
	assert.False(t, componentRepositoryRegex.MatchString("components/scanners/component:not-latest"))
}
