package images

import (
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/google/go-containerregistry/pkg/name"
)

type testURLProcessor struct{}

func (t *testURLProcessor) Process(repo string) string {
	return strings.Replace(repo, "/", "-", -1)
}

func TestComponentDirectory(t *testing.T) {
	t.Run("parse a Smithy component correctly", func(t *testing.T) {
		cr, _, err := ParseComponentRepository("testdata/components/scanners/codeql/component.yaml", "testdata/components/scanners/codeql")
		require.NoError(t, err)
		assert.Equal(t, path.Join(DefaultNamespace, "testdata/components/scanners/codeql"), cr.Repo())
		assert.ElementsMatch(t, []string{"latest"}, cr.Tags())
		assert.Equal(t, "testdata/components/scanners/codeql", cr.Directory())
		assert.Equal(t, DefaultRegistry, cr.Registry())
		assert.ElementsMatch(
			t,
			[]string{path.Join(DefaultRegistry, DefaultNamespace, "testdata/components/scanners/codeql:latest")},
			cr.URLs(),
		)
	})

	t.Run("an image reference that's not a local folder is not a component repository", func(t *testing.T) {
		cr, ref, err := ParseComponentRepository("testdata/components/scanners/codeql/component.yaml", "components/scanners/some-component")
		require.NoError(t, err)
		assert.Nil(t, cr)
		assert.Equal(t, name.DefaultRegistry, ref.RegistryStr())
	})

	t.Run("parse an external image", func(t *testing.T) {
		cr, parsedRef, err := ParseComponentRepository("testdata/components/scanners/codeql/component.yaml", "gosec:2.22.2")
		require.NoError(t, err)
		require.Nil(t, cr)
		assert.Equal(t, "index.docker.io", parsedRef.RegistryStr())
		assert.Equal(t, "library/gosec", parsedRef.RepositoryStr())
		assert.Equal(t, "2.22.2", parsedRef.TagStr())
	})

	t.Run("parse an image reference that is not part of the component", func(t *testing.T) {
		cr, parsedRef, err := ParseComponentRepository("testdata/components/scanners/codeql/component.yaml", "other-components/scanners/some-component")
		require.NoError(t, err)
		require.Nil(t, cr)
		assert.Equal(t, "other-components/scanners/some-component", parsedRef.Repository.RepositoryStr())
	})

	t.Run("parse a component image with a custom registry", func(t *testing.T) {
		cr, _, err := ParseComponentRepository(
			"testdata/components/scanners/codeql/component.yaml",
			"testdata/components/scanners/codeql",
			WithNamespace("some/namespace"),
			WithRegistry("kind-registry:5000"),
			WithTags("1.0.0-dev"),
		)
		require.NoError(t, err)
		assert.Equal(t, path.Join("some/namespace", "testdata/components/scanners/codeql"), cr.Repo())
		assert.ElementsMatch(t, []string{"1.0.0-dev"}, cr.Tags())
		assert.Equal(t, "testdata/components/scanners/codeql", cr.Directory())
		assert.Equal(t, "kind-registry:5000", cr.Registry())
		assert.ElementsMatch(
			t,
			[]string{path.Join("kind-registry:5000", "some/namespace", "testdata/components/scanners/codeql:1.0.0-dev")},
			cr.URLs(),
		)
	})

	t.Run("parse a component image with multiple tags", func(t *testing.T) {
		cr, _, err := ParseComponentRepository(
			"testdata/components/scanners/codeql/component.yaml",
			"testdata/components/scanners/codeql",
			WithNamespace("some/namespace"),
			WithRegistry("kind-registry:5000"),
			WithTags("1.0.0-dev", "latest", "1.0.0-amd64"),
		)
		require.NoError(t, err)
		assert.Equal(t, path.Join("some/namespace", "testdata/components/scanners/codeql"), cr.Repo())
		assert.ElementsMatch(t, []string{"1.0.0-dev", "1.0.0-amd64", "latest"}, cr.Tags())
		assert.Equal(t, "testdata/components/scanners/codeql", cr.Directory())
		assert.Equal(t, "kind-registry:5000", cr.Registry())
		assert.ElementsMatch(t,
			[]string{
				path.Join("kind-registry:5000", "some/namespace", "testdata/components/scanners/codeql:1.0.0-dev"),
				path.Join("kind-registry:5000", "some/namespace", "testdata/components/scanners/codeql:1.0.0-amd64"),
				path.Join("kind-registry:5000", "some/namespace", "testdata/components/scanners/codeql:latest"),
			},
			cr.URLs(),
		)
	})

	t.Run("parse a component helper image with multiple tags", func(t *testing.T) {
		cr, _, err := ParseComponentRepository(
			"testdata/components/scanners/codeql/component.yaml",
			"testdata/components/scanners/language-discovery",
			WithNamespace("some/namespace"),
			WithRegistry("kind-registry:5000"),
			WithTags("1.0.0-dev", "latest", "1.0.0-amd64"),
		)
		require.NoError(t, err)
		assert.Equal(t, path.Join("some/namespace", "testdata/components/scanners/language-discovery"), cr.Repo())
		assert.ElementsMatch(t, []string{"1.0.0-dev", "1.0.0-amd64", "latest"}, cr.Tags())
		assert.Equal(t, "testdata/components/scanners/language-discovery", cr.Directory())
		assert.Equal(t, "kind-registry:5000", cr.Registry())
		assert.ElementsMatch(t,
			[]string{
				path.Join("kind-registry:5000", "some/namespace", "testdata/components/scanners/language-discovery:1.0.0-dev"),
				path.Join("kind-registry:5000", "some/namespace", "testdata/components/scanners/language-discovery:1.0.0-amd64"),
				path.Join("kind-registry:5000", "some/namespace", "testdata/components/scanners/language-discovery:latest"),
			},
			cr.URLs(),
		)
	})

	t.Run("parse a component image with an image URL processor", func(t *testing.T) {
		cr, _, err := ParseComponentRepository(
			"testdata/components/scanners/codeql/component.yaml",
			"testdata/components/scanners/codeql/helper",
			WithNamespace("some/namespace"),
			WithRegistry("kind-registry:5000"),
			WithTags("1.0.0-dev", "latest", "1.0.0-amd64"),
			WithImageProcessor(&testURLProcessor{}),
		)
		require.NoError(t, err)
		assert.Equal(t, "some-namespace-testdata-components-scanners-codeql-helper", cr.Repo())
		assert.ElementsMatch(t, []string{"1.0.0-dev", "1.0.0-amd64", "latest"}, cr.Tags())
		assert.Equal(t, "testdata/components/scanners/codeql/helper", cr.Directory())
		assert.Equal(t, "kind-registry:5000", cr.Registry())
		assert.ElementsMatch(t,
			[]string{
				path.Join("kind-registry:5000", "some-namespace-testdata-components-scanners-codeql-helper:1.0.0-dev"),
				path.Join("kind-registry:5000", "some-namespace-testdata-components-scanners-codeql-helper:1.0.0-amd64"),
				path.Join("kind-registry:5000", "some-namespace-testdata-components-scanners-codeql-helper:latest"),
			},
			cr.URLs(),
		)
	})

	t.Run("parse an external image with a replacement", func(t *testing.T) {
		cr, parsedRef, err := ParseComponentRepository(
			"testdata/components/scanners/codeql/component.yaml",
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
			"testdata/components/scanners/codeql/component.yaml",
			"ghcr.io/smithy-security/components/scanners/some-component:2.22.2",
			WithImageReplacements(map[string]string{"index.docker.io/library/gosec:2.22.2": "index.docker.io/library/busybox:latest"}),
		)
		require.NoError(t, err)
		require.Nil(t, cr)
		assert.Equal(t, "smithy-security/components/scanners/some-component", parsedRef.Repository.RepositoryStr())
		assert.Equal(t, "2.22.2", parsedRef.TagStr())
	})

	t.Run("allow caller to replace any component image", func(t *testing.T) {
		cr, parsedRef, err := ParseComponentRepository(
			"testdata/components/scanners/codeql/component.yaml",
			"testdata/components/scanners/codeql",
			WithImageReplacements(map[string]string{"testdata/components/scanners/codeql": "some-registry.internal/codeql-image:v1.0.3"}),
		)
		require.NoError(t, err)
		require.Nil(t, cr)
		assert.Equal(t, "codeql-image", parsedRef.Repository.RepositoryStr())
		assert.Equal(t, "v1.0.3", parsedRef.TagStr())
	})
}
