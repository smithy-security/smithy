package dtrack

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

type Component struct {
	UUID               uuid.UUID           `json:"uuid,omitempty"`
	Author             string              `json:"author,omitempty"`
	Publisher          string              `json:"publisher,omitempty"`
	Group              string              `json:"group,omitempty"`
	Name               string              `json:"name"`
	Version            string              `json:"version"`
	Classifier         string              `json:"classifier,omitempty"`
	FileName           string              `json:"filename,omitempty"`
	Extension          string              `json:"extension,omitempty"`
	MD5                string              `json:"md5,omitempty"`
	SHA1               string              `json:"sha1,omitempty"`
	SHA256             string              `json:"sha256,omitempty"`
	SHA384             string              `json:"sha384,omitempty"`
	SHA512             string              `json:"sha512,omitempty"`
	SHA3_256           string              `json:"sha3_256,omitempty"`
	SHA3_384           string              `json:"sha3_384,omitempty"`
	SHA3_512           string              `json:"sha3_512,omitempty"`
	BLAKE2b_256        string              `json:"blake2b_256,omitempty"`
	BLAKE2b_384        string              `json:"blake2b_384,omitempty"`
	BLAKE2b_512        string              `json:"blake2b_512,omitempty"`
	BLAKE3             string              `json:"blake3,omitempty"`
	CPE                string              `json:"cpe,omitempty"`
	PURL               string              `json:"purl,omitempty"`
	SWIDTagID          string              `json:"swidTagId,omitempty"`
	Internal           bool                `json:"isInternal,omitempty"`
	Description        string              `json:"description,omitempty"`
	Copyright          string              `json:"copyright,omitempty"`
	License            string              `json:"license,omitempty"`
	ResolvedLicense    *License            `json:"resolvedLicense,omitempty"`
	DirectDependencies string              `json:"directDependencies,omitempty"`
	Notes              string              `json:"notes,omitempty"`
	ExternalReferences []ExternalReference `json:"externalReferences,omitempty"`
	Project            *Project            `json:"project,omitempty"`
}

type ExternalReference struct {
	Type    string `json:"type,omitempty"`
	URL     string `json:"url,omitempty"`
	Comment string `json:"comment,omitempty"`
}

type ComponentService struct {
	client *Client
}

func (cs ComponentService) Get(ctx context.Context, componentUUID uuid.UUID) (c Component, err error) {
	req, err := cs.client.newRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/component/%s", componentUUID))
	if err != nil {
		return
	}

	_, err = cs.client.doRequest(req, &c)
	return
}

func (cs ComponentService) GetAll(ctx context.Context, projectUUID uuid.UUID, po PageOptions) (p Page[Component], err error) {
	req, err := cs.client.newRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/component/project/%s", projectUUID), withPageOptions(po))
	if err != nil {
		return
	}

	res, err := cs.client.doRequest(req, &p.Items)
	if err != nil {
		return
	}

	p.TotalCount = res.TotalCount
	return
}

func (cs ComponentService) Create(ctx context.Context, projectUUID string, component Component) (c Component, err error) {
	req, err := cs.client.newRequest(ctx, http.MethodPut,
		fmt.Sprintf("/api/v1/component/project/%s", projectUUID),
		withBody(component))
	if err != nil {
		return
	}

	_, err = cs.client.doRequest(req, &c)
	return
}

func (cs ComponentService) Update(ctx context.Context, component Component) (c Component, err error) {
	req, err := cs.client.newRequest(ctx, http.MethodPost,
		"/api/v1/component",
		withBody(component))
	if err != nil {
		return
	}
	_, err = cs.client.doRequest(req, &c)
	return
}
