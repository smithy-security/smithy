package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/distribution/reference"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	v1 "github.com/smithy-security/smithy/pkg/types/v1"

	"github.com/smithy-security/smithy/smithyctl/internal/command/component"
	"github.com/smithy-security/smithy/smithyctl/pkg/images"
	"github.com/smithy-security/smithy/smithyctl/registry"
)

func TestSpecParser_Parse(t *testing.T) {
	var (
		ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
		ctrl        = gomock.NewController(t)
		mockFetcher = NewMockComponentFetcher(ctrl)
	)
	defer cancel()

	parser, err := NewSpecParser(mockFetcher, component.NewSpecParser(), nil)
	require.NoError(t, err)

	mockImageResolver := &imageResolver{}
	parser.imageResolver = mockImageResolver

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
				mockRemoteImageResolver := images.NewMockResolver(ctrl)
				gomock.InOrder(
					mockRemoteImageResolver.
						EXPECT().
						Resolve(ctx, "localhost:5000/components/targets/git-clone:latest").
						Return("localhost:5000/components/targets/git-clone:latest", nil),

					mockRemoteImageResolver.
						EXPECT().
						Resolve(ctx, "localhost:5000/components/reporters/json-logger:latest").
						Return("localhost:5000/components/reporters/json-logger:latest", nil),
				)

				mockImageResolver.remote = func() (images.Resolver, error) {
					return mockRemoteImageResolver, nil
				}
				mockImageResolver.local = nil
			},
			isValid: false,
		},
		{
			testCase:         "it should return an error because the yml spec is invalid",
			workflowSpecPath: "testdata/run/invalid/workflow.yml",
			expectations: func(t *testing.T) {
				mockRemoteImageResolver := images.NewMockResolver(ctrl)
				mockRemoteImageResolver.
					EXPECT().
					Resolve(ctx, "localhost:5000/components/targets/git-clone:latest").
					Return("localhost:5000/components/targets/git-clone:latest", nil)

				mockRemoteImageResolver.
					EXPECT().
					Resolve(ctx, "localhost:5000/components/reporters/json-logger:latest").
					Return("localhost:5000/components/reporters/json-logger:latest", nil)

				mockImageResolver.remote = func() (images.Resolver, error) {
					return mockRemoteImageResolver, nil
				}
				mockImageResolver.local = nil
			},
			isValid: false,
		},
		{
			testCase:         "it should correctly parse the yaml spec",
			workflowSpecPath: "./testdata/run/valid/workflow.yaml",
			overridesPath:    "./testdata/run/valid/overrides.yaml",
			expectations: func(t *testing.T) {
				ref, err := reference.Parse("localhost:5000/components/enrichers/enricher:latest")
				require.NoError(t, err)

				mockRemoteImageResolver := images.NewMockResolver(ctrl)
				mockLocalImageresolver := images.NewMockResolver(ctrl)

				gomock.InOrder(
					mockLocalImageresolver.
						EXPECT().
						Resolve(ctx, "components/targets/git-clone").
						Return("localhost:5000/components/targets/git-clone:latest", nil),

					mockFetcher.
						EXPECT().
						FetchPackage(ctx, ref).
						Return(&registry.FetchPackageResponse{
							Component: v1.Component{
								Name: "enricher",
								Steps: []v1.Step{
									{
										Image: "localhost:5000/components/enrichers/enricher:latest",
									},
								},
							},
						}, nil),

					mockRemoteImageResolver.
						EXPECT().
						Resolve(ctx, "localhost:5000/components/enrichers/enricher:latest").
						Return("localhost:5000/components/enrichers/enricher:latest", nil),

					mockRemoteImageResolver.
						EXPECT().
						Resolve(ctx, "localhost:5000/components/reporters/json-logger:latest").
						Return("localhost:5000/components/reporters/json-logger:latest", nil),
				)

				mockImageResolver.remote = func() (images.Resolver, error) {
					return mockRemoteImageResolver, nil
				}

				mockImageResolver.local = func(
					ctx context.Context,
					componentPath string,
				) (images.Resolver, error) {
					require.Equal(t, "testdata/targets/git-clone/component.yaml", componentPath)
					return mockLocalImageresolver, nil
				}
			},
			isValid: true,
		},
		{
			testCase:         "it should correctly parse the yml spec",
			workflowSpecPath: "./testdata/run/valid/workflow.yml",
			isValid:          true,
			expectations: func(t *testing.T) {
				mockRemoteImageResolver := images.NewMockResolver(ctrl)
				mockLocalImageResolver := images.NewMockResolver(ctrl)
				gomock.InOrder(
					mockRemoteImageResolver.
						EXPECT().
						Resolve(ctx, "localhost:5000/components/targets/git-clone:latest").
						Return("localhost:5000/components/targets/git-clone:latest", nil),

					mockLocalImageResolver.
						EXPECT().
						Resolve(ctx, "components/targets/git-clone").
						Return("localhost:5000/components/targets/git-clone:latest", nil),

					mockRemoteImageResolver.
						EXPECT().
						Resolve(ctx, "localhost:5000/components/reporters/json-logger:latest").
						Return("localhost:5000/components/reporters/json-logger:latest", nil),
				)

				mockImageResolver.remote = func() (images.Resolver, error) {
					return mockRemoteImageResolver, nil
				}

				mockImageResolver.local = func(
					ctx context.Context,
					componentPath string,
				) (images.Resolver, error) {
					require.Equal(t, "testdata/targets/git-clone/component.yaml", componentPath)
					return mockLocalImageResolver, nil
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
					SpecPath:      tt.workflowSpecPath,
					OverridesPath: tt.overridesPath,
				})
			if tt.isValid {
				require.NoError(t, err, wf.Validate())
				return
			}
			assert.Error(t, err)
		})
	}
}
