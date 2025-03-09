package images

import (
	"testing"

	v1 "github.com/smithy-security/smithy/pkg/types/v1"
	"github.com/stretchr/testify/require"
)

func TestComponentDirectory(t *testing.T) {
	cr, _, err := ParseComponentRepository("scanners/some-component/component.yaml", "scanners/some-component")
	require.NoError(t, err)
	require.Equal(t, "scanners/some-component", cr.Path())
	require.Equal(t, "scanners/some-component", cr.Repo())
	require.Equal(t, v1.ComponentTypeScanner, cr.Type())
	require.Equal(t, "some-component", cr.Name())

	cr, _, err = ParseComponentRepository("new-components/scanners/some-component/component.yaml", "new-components/scanners/some-component")
	require.NoError(t, err)
	require.Equal(t, "scanners/some-component", cr.Path())
	require.Equal(t, "new-components/scanners/some-component", cr.Repo())
	require.Equal(t, v1.ComponentTypeScanner, cr.Type())
	require.Equal(t, "some-component", cr.Name())

	cr, parsedRef, err := ParseComponentRepository("new-components/scanners/some-component/component.yaml", "gosec:2.22.2")
	require.ErrorIs(t, err, ErrNotAComponentRepo)
	require.Nil(t, cr)
	require.Equal(t, "gosec", parsedRef.Repository.RepositoryStr())

	cr, parsedRef, err = ParseComponentRepository("new-components/scanners/some-component/component.yaml", "components/scanners/some-component")
	require.ErrorIs(t, err, ErrNotAComponentRepo)
	require.Nil(t, cr)
	require.Equal(t, "components/scanners/some-component", parsedRef.Repository.RepositoryStr())
}
