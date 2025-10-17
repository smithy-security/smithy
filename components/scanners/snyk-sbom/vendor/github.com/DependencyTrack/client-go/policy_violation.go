package dtrack

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/google/uuid"
)

type PolicyViolation struct {
	UUID            uuid.UUID
	Component       Component          `json:"component"`
	Project         Project            `json:"project"`
	PolicyCondition *PolicyCondition   `json:"policyCondition,omitempty"`
	Type            string             `json:"type"`
	Text            string             `json:"text"`
	Analysis        *ViolationAnalysis `json:"analysis,omitempty"`
}

type PolicyViolationService struct {
	client *Client
}

func (pvs PolicyViolationService) GetAll(ctx context.Context, suppressed bool, po PageOptions) (p Page[PolicyViolation], err error) {
	params := map[string]string{
		"suppressed": strconv.FormatBool(suppressed),
	}

	req, err := pvs.client.newRequest(ctx, http.MethodGet, "/api/v1/violation", withParams(params), withPageOptions(po))
	if err != nil {
		return
	}

	res, err := pvs.client.doRequest(req, &p.Items)
	if err != nil {
		return
	}

	p.TotalCount = res.TotalCount
	return
}

func (pvs PolicyViolationService) GetAllForProject(ctx context.Context, projectUUID uuid.UUID, suppressed bool, po PageOptions) (p Page[PolicyViolation], err error) {
	params := map[string]string{
		"suppressed": strconv.FormatBool(suppressed),
	}

	req, err := pvs.client.newRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/violation/project/%s", projectUUID), withParams(params), withPageOptions(po))
	if err != nil {
		return
	}

	res, err := pvs.client.doRequest(req, &p.Items)
	if err != nil {
		return
	}

	p.TotalCount = res.TotalCount
	return
}

func (pvs PolicyViolationService) GetAllForComponent(ctx context.Context, componentUUID uuid.UUID, suppressed bool, po PageOptions) (p Page[PolicyViolation], err error) {
	params := map[string]string{
		"suppressed": strconv.FormatBool(suppressed),
	}

	req, err := pvs.client.newRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/violation/component/%s", componentUUID), withParams(params), withPageOptions(po))
	if err != nil {
		return
	}

	res, err := pvs.client.doRequest(req, &p.Items)
	if err != nil {
		return
	}

	p.TotalCount = res.TotalCount
	return
}
