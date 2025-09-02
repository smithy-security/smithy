package dtrack

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

type VEXService struct {
	client *Client
}

type VEXUploadRequest struct {
	ProjectUUID    *uuid.UUID `json:"project,omitempty"`
	ProjectName    string     `json:"projectName,omitempty"`
	ProjectVersion string     `json:"projectVersion,omitempty"`
	VEX            string     `json:"vex"`
}

func (vs VEXService) ExportCycloneDX(ctx context.Context, projectUUID uuid.UUID) (vex string, err error) {
	req, err := vs.client.newRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/vex/cyclonedx/project/%s", projectUUID))
	if err != nil {
		return
	}

	req.Header.Set("Accept", "application/vnd.cyclonedx+json")

	_, err = vs.client.doRequest(req, &vex)
	return
}

func (vs VEXService) Upload(ctx context.Context, uploadReq VEXUploadRequest) (err error) {
	req, err := vs.client.newRequest(ctx, http.MethodPut, "/api/v1/vex", withBody(uploadReq))
	if err != nil {
		return
	}

	_, err = vs.client.doRequest(req, nil)
	return
}
