package dtrack

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

const (
	RepositoryTypeCargo       = "CARGO"
	RepositoryTypeComposer    = "COMPOSER"
	RepositoryTypeCpan        = "CPAN"
	RepositoryTypeGem         = "GEM"
	RepositoryTypeGithub      = "GITHUB"
	RepositoryTypeGoModules   = "GO_MODULES"
	RepositoryTypeHex         = "HEX"
	RepositoryTypeMaven       = "MAVEN"
	RepositoryTypeNpm         = "NPM"
	RepositoryTypeNuget       = "NUGET"
	RepositoryTypePypi        = "PYPI"
	RepositoryTypeUnsupported = "UNSUPPORTED"
)

type RepositoryType string

type Repository struct {
	Type                   RepositoryType `json:"type"`
	Identifier             string         `json:"identifier"`
	Url                    string         `json:"url"`
	ResolutionOrder        int            `json:"resolutionOrder"`
	Enabled                bool           `json:"enabled"`
	Internal               bool           `json:"internal"`
	AuthenticationRequired bool           `json:"authenticationRequired"`
	Username               string         `json:"username,omitempty"`
	Password               string         `json:"password,omitempty"`
	UUID                   uuid.UUID      `json:"uuid,omitempty"`
}

type RepositoryMetaComponent struct {
	LatestVersion string `json:"latestVersion"`
}

type RepositoryService struct {
	client *Client
}

func (rs RepositoryService) GetMetaComponent(ctx context.Context, purl string) (r RepositoryMetaComponent, err error) {
	params := map[string]string{
		"purl": purl,
	}

	req, err := rs.client.newRequest(ctx, http.MethodGet, "/api/v1/repository/latest", withParams(params))
	if err != nil {
		return
	}

	_, err = rs.client.doRequest(req, &r)
	return
}

func (rs RepositoryService) GetAll(ctx context.Context, po PageOptions) (p Page[Repository], err error) {
	req, err := rs.client.newRequest(ctx, http.MethodGet, "/api/v1/repository", withPageOptions(po))
	if err != nil {
		return
	}

	res, err := rs.client.doRequest(req, &p.Items)
	if err != nil {
		return
	}

	p.TotalCount = res.TotalCount
	return
}

func (rs RepositoryService) GetByType(ctx context.Context, repoType RepositoryType, po PageOptions) (p Page[Repository], err error) {
	req, err := rs.client.newRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/repository/%s", repoType), withPageOptions(po))
	if err != nil {
		return
	}

	res, err := rs.client.doRequest(req, &p.Items)
	if err != nil {
		return
	}

	p.TotalCount = res.TotalCount
	return
}

func (rs RepositoryService) Create(ctx context.Context, repo Repository) (r Repository, err error) {
	req, err := rs.client.newRequest(ctx, http.MethodPut, "/api/v1/repository", withBody(repo))
	if err != nil {
		return
	}

	_, err = rs.client.doRequest(req, &r)
	return
}
func (rs RepositoryService) Update(ctx context.Context, repo Repository) (r Repository, err error) {
	req, err := rs.client.newRequest(ctx, http.MethodPost, "/api/v1/repository", withBody(repo))
	if err != nil {
		return
	}

	_, err = rs.client.doRequest(req, &r)
	return
}

func (rs RepositoryService) Delete(ctx context.Context, reposUUID uuid.UUID) (err error) {
	req, err := rs.client.newRequest(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/repository/%s", reposUUID.String()))
	if err != nil {
		return
	}

	_, err = rs.client.doRequest(req, nil)
	return
}
