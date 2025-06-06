package findingsclient_test

import (
	"context"
	"errors"
	"maps"
	"net"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/smithy-security/smithy/sdk/component"
	"github.com/smithy-security/smithy/sdk/component/store"
	findingsclient "github.com/smithy-security/smithy/sdk/component/store/remote/findings-client"
	"github.com/smithy-security/smithy/sdk/component/utils"
	"github.com/smithy-security/smithy/sdk/component/uuid"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	v1 "github.com/smithy-security/smithy/sdk/gen/findings_service/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

type (
	FindingsClientTestSuite struct {
		suite.Suite

		findingsServiceClient component.Storer
		fakeFindingsService   fakeFindingsService
	}

	fakeFindingsService struct {
		grpcServer *grpc.Server
		v1.UnimplementedFindingsServiceServer
		findings         map[string]map[uint64]*ocsf.VulnerabilityFinding
		findingIDCounter uint64
	}
)

func (ffs *fakeFindingsService) GetFindings(_ context.Context, req *v1.GetFindingsRequest) (*v1.GetFindingsResponse, error) {
	if req == nil {
		return &v1.GetFindingsResponse{}, errors.New("create findings request is nil")
	}

	if req.Page != nil && req.PageSize == nil {
		return &v1.GetFindingsResponse{}, status.Errorf(codes.InvalidArgument, "when requesting a specific page you need to set the page size")
	} else if req.Page != nil && *req.PageSize == 0 {
		return &v1.GetFindingsResponse{}, status.Errorf(codes.InvalidArgument, "page size when set should be greater than 0")
	}

	findings, ok := ffs.findings[req.Id]
	if !ok {
		return &v1.GetFindingsResponse{}, status.Errorf(codes.NotFound, "findings not found")
	}

	var requestedFindingIDs []uint64
	if req.Page != nil {
		offset := int(*req.Page * *req.PageSize)
		if offset > len(findings) {
			return &v1.GetFindingsResponse{}, status.Errorf(codes.InvalidArgument, "page is out of bounds")
		} else {
			requestedFindingIDs = slices.Sorted(maps.Keys(findings))
			if offset+int(*req.PageSize) < len(requestedFindingIDs) {
				requestedFindingIDs = requestedFindingIDs[offset:int(*req.PageSize)]
			} else {
				requestedFindingIDs = requestedFindingIDs[offset:]
			}
		}
	} else {
		requestedFindingIDs = slices.Sorted(maps.Keys(findings))
	}

	return &v1.GetFindingsResponse{
		Findings: slices.Collect(
			utils.MapSlice(
				slices.Values(requestedFindingIDs),
				func(findingID uint64) *v1.Finding {
					return &v1.Finding{
						Id:      findingID,
						Details: findings[findingID],
					}
				},
			),
		),
	}, nil
}

func (ffs *fakeFindingsService) UpdateFindings(_ context.Context, req *v1.UpdateFindingsRequest) (*v1.UpdateFindingsResponse, error) {
	if req == nil {
		return &v1.UpdateFindingsResponse{}, errors.New("create findings request is nil")
	}

	_, ok := ffs.findings[req.Id]
	if !ok {
		return &v1.UpdateFindingsResponse{}, status.Errorf(codes.NotFound, "findings not found")
	}

	for _, finding := range req.Findings {
		if _, ok := ffs.findings[req.Id]; !ok {
			ffs.findings[req.Id] = make(map[uint64]*ocsf.VulnerabilityFinding)
		}
		ffs.findings[req.Id][finding.Id] = finding.Details
	}

	return &v1.UpdateFindingsResponse{}, nil
}

func (ffs *fakeFindingsService) CreateFindings(_ context.Context, req *v1.CreateFindingsRequest) (*v1.CreateFindingsResponse, error) {
	if req == nil {
		return &v1.CreateFindingsResponse{}, errors.New("create findings request is nil")
	}

	// Initialising empty findings to avoid panics.
	if ffs.findings == nil {
		ffs.findings = make(map[string]map[uint64]*ocsf.VulnerabilityFinding)
	}

	for _, finding := range req.Findings {
		_, ok := ffs.findings[req.Id]
		if !ok {
			ffs.findings[req.Id] = make(map[uint64]*ocsf.VulnerabilityFinding)
		}

		ffs.findingIDCounter++
		ffs.findings[req.Id][ffs.findingIDCounter] = finding
	}

	return &v1.CreateFindingsResponse{}, nil
}

func TestFindingsClientTestSuite(t *testing.T) {
	suite.Run(t, new(FindingsClientTestSuite))
}

func (s *FindingsClientTestSuite) SetupSuite() {
	lis, err := net.Listen("tcp", "localhost:50051")
	require.NoError(s.T(), err)

	fakeService := &fakeFindingsService{}
	grpcServer := grpc.NewServer()

	v1.RegisterFindingsServiceServer(grpcServer, fakeService)
	s.fakeFindingsService = fakeFindingsService{
		grpcServer: grpcServer,
	}

	require.NoError(s.T(), os.Setenv("SMITHY_REMOTE_CLIENT_PAGE_SIZE", "1"))
	s.findingsServiceClient, err = findingsclient.New()
	require.NoError(s.T(), err)

	go s.fakeFindingsService.grpcServer.Serve(lis)
}

func (s *FindingsClientTestSuite) TearDownSuite() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(s.T(), s.findingsServiceClient.Close(ctx))
	s.fakeFindingsService.grpcServer.GracefulStop()
}

func (s *FindingsClientTestSuite) TestClient() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var (
		instanceID = uuid.New()
		findings   = []*ocsf.VulnerabilityFinding{
			{
				ActivityId: ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
			},
			{
				ActivityId: ocsf.VulnerabilityFinding_ACTIVITY_ID_UPDATE,
			},
		}
	)

	s.T().Run("it should return a not found error when no findings are associated with the instance id", func(t *testing.T) {
		ffs, err := s.findingsServiceClient.Read(ctx, instanceID)
		require.ErrorIs(s.T(), err, store.ErrNoFindingsFound)
		assert.Empty(t, ffs)
	})

	s.T().Run("it should successfully create new findings", func(t *testing.T) {
		require.NoError(s.T(), s.findingsServiceClient.Write(ctx, instanceID, findings))
	})

	s.T().Run("and after retrieving them", func(t *testing.T) {
		ffs, err := s.findingsServiceClient.Read(ctx, instanceID)
		require.NoError(s.T(), err)
		require.Len(t, ffs, 2)
	})

	s.T().Run("it should successfully update existing findings", func(t *testing.T) {
		for _, finding := range findings {
			finding.TypeUid = 120
		}
		require.NoError(s.T(), s.findingsServiceClient.Update(
			ctx,
			instanceID,
			[]*vf.VulnerabilityFinding{
				{
					ID:      1,
					Finding: findings[0],
				},
				{
					ID:      2,
					Finding: findings[1],
				},
			}),
		)
	})

	s.T().Run("it should returns the created findings", func(t *testing.T) {
		ffs, err := s.findingsServiceClient.Read(ctx, instanceID)
		require.NoError(s.T(), err)
		assert.Len(t, ffs, 2)
	})
}
