package dtrack

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

type ProjectProperty struct {
	Group       string `json:"groupName"`
	Name        string `json:"propertyName"`
	Value       string `json:"propertyValue"`
	Type        string `json:"propertyType"`
	Description string `json:"description"`
}

type ProjectPropertyService struct {
	client *Client
}

func (ps ProjectPropertyService) GetAll(ctx context.Context, projectUUID uuid.UUID, po PageOptions) (p Page[ProjectProperty], err error) {
	req, err := ps.client.newRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/project/%s/property", projectUUID), withPageOptions(po))
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

func (ps ProjectPropertyService) Create(ctx context.Context, projectUUID uuid.UUID, property ProjectProperty) (p ProjectProperty, err error) {
	req, err := ps.client.newRequest(ctx, http.MethodPut, fmt.Sprintf("/api/v1/project/%s/property", projectUUID), withBody(property))
	if err != nil {
		return
	}

	_, err = ps.client.doRequest(req, &p)
	return
}

func (ps ProjectPropertyService) Update(ctx context.Context, projectUUID uuid.UUID, property ProjectProperty) (p ProjectProperty, err error) {
	req, err := ps.client.newRequest(ctx, http.MethodPost, fmt.Sprintf("/api/v1/project/%s/property", projectUUID), withBody(property))
	if err != nil {
		return
	}

	_, err = ps.client.doRequest(req, &p)
	return
}

func (ps ProjectPropertyService) Delete(ctx context.Context, projectUUID uuid.UUID, groupName, propertyName string) (err error) {
	property := ProjectProperty{
		Group: groupName,
		Name:  propertyName,
	}

	req, err := ps.client.newRequest(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/project/%s/property", projectUUID), withBody(property))
	if err != nil {
		return
	}

	_, err = ps.client.doRequest(req, nil)
	return
}
