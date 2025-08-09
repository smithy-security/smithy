package dtrack

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/google/uuid"
)

type Project struct {
	UUID               uuid.UUID           `json:"uuid,omitempty"`
	Author             string              `json:"author,omitempty"`
	Publisher          string              `json:"publisher,omitempty"`
	Group              string              `json:"group,omitempty"`
	Name               string              `json:"name,omitempty"`
	Description        string              `json:"description,omitempty"`
	Version            string              `json:"version,omitempty"`
	Classifier         string              `json:"classifier,omitempty"`
	CPE                string              `json:"cpe,omitempty"`
	PURL               string              `json:"purl,omitempty"`
	SWIDTagID          string              `json:"swidTagId,omitempty"`
	DirectDependencies string              `json:"directDependencies,omitempty"`
	Properties         []ProjectProperty   `json:"properties,omitempty"`
	Tags               []Tag               `json:"tags,omitempty"`
	Active             bool                `json:"active"`
	IsLatest           *bool               `json:"isLatest,omitempty"` // Since v4.12.0
	Metrics            ProjectMetrics      `json:"metrics"`
	ParentRef          *ParentRef          `json:"parent,omitempty"`
	LastBOMImport      int                 `json:"lastBomImport"`
	ExternalReferences []ExternalReference `json:"externalReferences,omitempty"`
}

type ParentRef struct {
	UUID uuid.UUID `json:"uuid,omitempty"`
}

type ProjectService struct {
	client *Client
}

func (ps ProjectService) Get(ctx context.Context, projectUUID uuid.UUID) (p Project, err error) {
	req, err := ps.client.newRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/project/%s", projectUUID))
	if err != nil {
		return
	}

	_, err = ps.client.doRequest(req, &p)
	return
}

func (ps ProjectService) GetAll(ctx context.Context, po PageOptions) (p Page[Project], err error) {
	req, err := ps.client.newRequest(ctx, http.MethodGet, "/api/v1/project", withPageOptions(po))
	if err != nil {
		return
	}

	res, err := ps.client.doRequest(req, &p.Items)
	if err != nil {
		return
	}

	p.TotalCount = res.TotalCount
	return
}

func (ps ProjectService) Latest(ctx context.Context, name string) (p Project, err error) {
	req, err := ps.client.newRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/project/latest/%s", url.PathEscape(name)))
	if err != nil {
		return
	}
	_, err = ps.client.doRequest(req, &p)
	return
}

func (ps ProjectService) GetProjectsForName(ctx context.Context, name string, excludeInactive, onlyRoot bool) (p []Project, err error) {
	params := map[string]string{
		"name":            name,
		"excludeInactive": strconv.FormatBool(excludeInactive),
		"onlyRoot":        strconv.FormatBool(onlyRoot),
	}

	req, err := ps.client.newRequest(ctx, http.MethodGet, "/api/v1/project", withParams(params))
	if err != nil {
		return
	}

	_, err = ps.client.doRequest(req, &p)
	return
}

func (ps ProjectService) Create(ctx context.Context, project Project) (p Project, err error) {
	req, err := ps.client.newRequest(ctx, http.MethodPut, "/api/v1/project", withBody(project))
	if err != nil {
		return
	}

	_, err = ps.client.doRequest(req, &p)
	return
}

func (ps ProjectService) Patch(ctx context.Context, projectUUID uuid.UUID, project Project) (p Project, err error) {
	req, err := ps.client.newRequest(ctx, http.MethodPatch, fmt.Sprintf("/api/v1/project/%s", projectUUID), withBody(project))
	if err != nil {
		return
	}

	_, err = ps.client.doRequest(req, &p)
	return
}

func (ps ProjectService) Update(ctx context.Context, project Project) (p Project, err error) {
	req, err := ps.client.newRequest(ctx, http.MethodPost, "/api/v1/project", withBody(project))
	if err != nil {
		return
	}

	_, err = ps.client.doRequest(req, &p)
	return
}

func (ps ProjectService) Delete(ctx context.Context, projectUUID uuid.UUID) (err error) {
	req, err := ps.client.newRequest(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/project/%s", projectUUID))
	if err != nil {
		return
	}

	_, err = ps.client.doRequest(req, nil)
	return
}

func (ps ProjectService) Lookup(ctx context.Context, name, version string) (p Project, err error) {
	params := map[string]string{
		"name":    name,
		"version": version,
	}

	req, err := ps.client.newRequest(ctx, http.MethodGet, "/api/v1/project/lookup", withParams(params))
	if err != nil {
		return
	}

	_, err = ps.client.doRequest(req, &p)
	return
}

func (ps ProjectService) GetAllByTag(ctx context.Context, tag string, excludeInactive, onlyRoot bool, po PageOptions) (p Page[Project], err error) {
	pathParams := map[string]string{
		"tag": tag,
	}
	params := map[string]string{
		"excludeInactive": strconv.FormatBool(excludeInactive),
		"onlyRoot":        strconv.FormatBool(onlyRoot),
	}

	req, err := ps.client.newRequest(ctx, http.MethodGet, "/api/v1/project/tag/{tag}", withPathParams(pathParams), withParams(params), withPageOptions(po))
	if err != nil {
		return
	}

	res, err := ps.client.doRequest(req, &p.Items)
	if err != nil {
		return
	}

	p.TotalCount = res.TotalCount
	return
}

type ProjectCloneRequest struct {
	ProjectUUID             uuid.UUID `json:"project"`
	Version                 string    `json:"version"`
	IncludeACL              bool      `json:"includeACL"`
	IncludeAuditHistory     bool      `json:"includeAuditHistory"`
	IncludeComponents       bool      `json:"includeComponents"`
	IncludePolicyViolations *bool     `json:"includePolicyViolations,omitempty"` // Since v4.11.0
	IncludeProperties       bool      `json:"includeProperties"`
	IncludeServices         bool      `json:"includeServices"`
	IncludeTags             bool      `json:"includeTags"`
	MakeCloneLatest         *bool     `json:"makeCloneLatest,omitempty"` // Since v4.12.0
}

// Clone triggers a cloning operation.
// An EventToken is only returned for server versions 4.11.0 and newer.
func (ps ProjectService) Clone(ctx context.Context, cloneReq ProjectCloneRequest) (token EventToken, err error) {
	req, err := ps.client.newRequest(ctx, http.MethodPut, "/api/v1/project/clone", withBody(cloneReq))
	if err != nil {
		return
	}

	if ps.client.isServerVersionAtLeast("4.11.0") {
		var tokenResponse EventTokenResponse
		_, err = ps.client.doRequest(req, &tokenResponse)
		token = tokenResponse.Token
	} else {
		_, err = ps.client.doRequest(req, nil)
	}

	return
}
