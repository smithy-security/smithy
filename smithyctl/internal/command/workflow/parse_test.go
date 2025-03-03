package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/distribution/reference"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/smithy-security/smithy/smithyctl/internal/command/component"
	"github.com/smithy-security/smithy/smithyctl/internal/images"
	dockerimages "github.com/smithy-security/smithy/smithyctl/internal/images/docker"
	"github.com/smithy-security/smithy/smithyctl/registry"
)

func TestSpecParser_Parse(t *testing.T) {
	var (
		ctx, cancel       = context.WithTimeout(context.Background(), time.Minute)
		ctrl              = gomock.NewController(t)
		mockFetcher       = NewMockComponentFetcher(ctrl)
		mockImageResolver *images.MockResolver
	)
	defer cancel()

	parser, err := NewSpecParser(mockFetcher, component.NewSpecParser())
	require.NoError(t, err)

	parser.remoteImagesResolver = func() images.Resolver {
		return mockImageResolver
	}

	for _, tt := range []struct {
		testCase         string
		workflowSpecPath string
		overridesPath    string
		expectations     func(t *testing.T)
		isValid          bool
	}{
		{
			testCase:         "it should return an error because the path does not exist",
			workflowSpecPath: "/some/path/that/does/not/exist",
			isValid:          false,
		},
		{
			testCase:         "it should return an error because the yaml spec is invalid",
			workflowSpecPath: "testdata/run/invalid/workflow.yaml",
			expectations: func(t *testing.T) {
				mockImageResolver = images.NewMockResolver(ctrl)
				mockImageResolver.
					EXPECT().
					Resolve(ctx, "localhost:5000/components/targets/git-clone:latest").
					Return("localhost:5000/components/targets/git-clone:latest", nil)

				mockImageResolver.
					EXPECT().
					Resolve(ctx, "localhost:5000/components/reporters/json-logger:latest").
					Return("localhost:5000/components/reporters/json-logger:latest", nil)

			},
			isValid: false,
		},
		{
			testCase:         "it should return an error because the yml spec is invalid",
			workflowSpecPath: "testdata/run/invalid/workflow.yml",
			expectations: func(t *testing.T) {
				mockImageResolver = images.NewMockResolver(ctrl)
				mockImageResolver.
					EXPECT().
					Resolve(ctx, "localhost:5000/components/targets/git-clone:latest").
					Return("localhost:5000/components/targets/git-clone:latest", nil)

				mockImageResolver.
					EXPECT().
					Resolve(ctx, "localhost:5000/components/reporters/json-logger:latest").
					Return("localhost:5000/components/reporters/json-logger:latest", nil)
			},
			isValid: false,
		},
		{
			testCase:         "it should correctly parse the yaml spec",
			workflowSpecPath: "./testdata/run/valid/workflow.yaml",
			overridesPath:    "./testdata/run/valid/overrides.yaml",
			expectations: func(t *testing.T) {
				mockImageResolver = images.NewMockResolver(ctrl)

				ref, err := reference.Parse("localhost:5000/components/enrichers/enricher:latest")
				require.NoError(t, err)
				mockFetcher.
					EXPECT().
					FetchPackage(ctx, ref).
					Return(&registry.FetchPackageResponse{}, nil)

				parser.localImagesResolver = func(
					ctx context.Context,
					c dockerimages.Client,
					componentPath string,
					bof ...dockerimages.BuilderOptionFn,
				) (images.Resolver, error) {
					require.Nil(t, c)
					require.Equal(t, "", componentPath)
					require.Empty(t, bof)

					return mockImageResolver, nil
				}

				mockImageResolver.
					EXPECT().
					Resolve(ctx, "localhost:5000/components/targets/git-clone:latest").
					Return("localhost:5000/components/targets/git-clone:latest", nil)

				mockImageResolver.
					EXPECT().
					Resolve(ctx, "localhost:5000/components/reporters/json-logger:latest").
					Return("localhost:5000/components/reporters/json-logger:latest", nil)
			},
			isValid: true,
		},
		{
			testCase:         "it should correctly parse the yml spec",
			workflowSpecPath: "./testdata/run/valid/workflow.yml",
			isValid:          true,
			expectations: func(t *testing.T) {
				mockImageResolver = images.NewMockResolver(ctrl)

				mockImageResolver.
					EXPECT().
					Resolve(ctx, "localhost:5000/components/targets/git-clone:latest").
					Return("localhost:5000/components/targets/git-clone:latest", nil)

				mockImageResolver.
					EXPECT().
					Resolve(ctx, "localhost:5000/components/targets/git-clone:latest").
					Return("localhost:5000/components/targets/git-clone:latest", nil)

				mockImageResolver.
					EXPECT().
					Resolve(ctx, "localhost:5000/components/reporters/json-logger:latest").
					Return("localhost:5000/components/reporters/json-logger:latest", nil)

				parser.localImagesResolver = func(
					ctx context.Context,
					c dockerimages.Client,
					componentPath string,
					bof ...dockerimages.BuilderOptionFn,
				) (images.Resolver, error) {
					require.Nil(t, c)
					require.Equal(t, "", componentPath)
					require.Empty(t, bof)

					return mockImageResolver, nil
				}
			},
		},
	} {
		t.Run(tt.testCase, func(t *testing.T) {
			if tt.expectations != nil {
				tt.expectations(t)
			}

			wf, err := parser.Parse(
				ctx,
				ParserConfig{
					SpecPath:             tt.workflowSpecPath,
					OverridesPath:        tt.overridesPath,
					BuildComponentImages: false,
				})
			if tt.isValid {
				require.NoError(t, err, wf.Validate())
				return
			}
			assert.Error(t, err)
		})
	}
}
