package dtrack

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/google/uuid"
)

type OIDCService struct {
	client *Client
}

type OIDCGroup struct {
	Name string    `json:"name,omitempty"`
	UUID uuid.UUID `json:"uuid,omitempty"`
}

type OIDCMappingRequest struct {
	Team  uuid.UUID `json:"team"`
	Group uuid.UUID `json:"group"`
}

type OIDCMapping struct {
	Group OIDCGroup `json:"group"`
	UUID  uuid.UUID `json:"uuid"`
}

func (s OIDCService) Available(ctx context.Context) (available bool, err error) {
	req, err := s.client.newRequest(ctx, http.MethodGet, "/api/v1/oidc/available", withAcceptContentType("text/plain"))
	if err != nil {
		return
	}

	var value string

	_, err = s.client.doRequest(req, &value)
	if err != nil {
		return
	}
	available, err = strconv.ParseBool(value)
	return
}

func (s OIDCService) GetAllGroups(ctx context.Context, po PageOptions) (p Page[OIDCGroup], err error) {
	req, err := s.client.newRequest(ctx, http.MethodGet, "/api/v1/oidc/group", withPageOptions(po))
	if err != nil {
		return
	}

	res, err := s.client.doRequest(req, &p.Items)
	if err != nil {
		return
	}

	p.TotalCount = res.TotalCount
	return
}

func (s OIDCService) CreateGroup(ctx context.Context, name string) (g OIDCGroup, err error) {
	req, err := s.client.newRequest(ctx, http.MethodPut, "/api/v1/oidc/group", withBody(OIDCGroup{Name: name}))
	if err != nil {
		return
	}

	_, err = s.client.doRequest(req, &g)
	return
}
func (s OIDCService) UpdateGroup(ctx context.Context, group OIDCGroup) (g OIDCGroup, err error) {
	req, err := s.client.newRequest(ctx, http.MethodPost, "/api/v1/oidc/group", withBody(group))
	if err != nil {
		return
	}

	_, err = s.client.doRequest(req, &g)
	return
}

func (s OIDCService) DeleteGroup(ctx context.Context, groupUUID uuid.UUID) (err error) {
	req, err := s.client.newRequest(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/oidc/group/%s", groupUUID.String()))
	if err != nil {
		return
	}

	_, err = s.client.doRequest(req, nil)
	return
}

func (s OIDCService) GetAllTeamsOf(ctx context.Context, group OIDCGroup, po PageOptions) (p Page[Team], err error) {
	req, err := s.client.newRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/oidc/group/%s/team", group.UUID.String()), withPageOptions(po))
	if err != nil {
		return
	}

	res, err := s.client.doRequest(req, &p.Items)
	if err != nil {
		return
	}

	p.TotalCount = res.TotalCount
	return
}

func (s OIDCService) AddTeamMapping(ctx context.Context, mapping OIDCMappingRequest) (m OIDCMapping, err error) {
	req, err := s.client.newRequest(ctx, http.MethodPut, "/api/v1/oidc/mapping", withBody(mapping))
	if err != nil {
		return
	}

	_, err = s.client.doRequest(req, &m)
	return
}

func (s OIDCService) RemoveTeamMapping(ctx context.Context, mappingID uuid.UUID) (err error) {
	req, err := s.client.newRequest(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/oidc/mapping/%s", mappingID.String()))
	if err != nil {
		return
	}

	_, err = s.client.doRequest(req, nil)
	return
}
