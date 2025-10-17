package dtrack

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

const (
	PermissionAccessManagement        = "ACCESS_MANAGEMENT"
	PermissionBOMUpload               = "BOM_UPLOAD"
	PermissionPolicyManagement        = "POLICY_MANAGEMENT"
	PermissionPolicyViolationAnalysis = "POLICY_VIOLATION_ANALYSIS"
	PermissionPortfolioManagement     = "PORTFOLIO_MANAGEMENT"
	PermissionProjectCreationUpload   = "PROJECT_CREATION_UPLOAD"
	PermissionSystemConfiguration     = "SYSTEM_CONFIGURATION"
	PermissionTagManagement           = "TAG_MANAGEMENT"
	PermissionViewBadges              = "VIEW_BADGES"
	PermissionViewPolicyViolation     = "VIEW_POLICY_VIOLATION"
	PermissionViewPortfolio           = "VIEW_PORTFOLIO"
	PermissionViewVulnerability       = "VIEW_VULNERABILITY"
	PermissionVulnerabilityAnalysis   = "VULNERABILITY_ANALYSIS"
	PermissionVulnerabilityManagement = "VULNERABILITY_MANAGEMENT"
)

type PermissionService struct {
	client *Client
}

type Permission struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (ps PermissionService) GetAll(ctx context.Context, po PageOptions) (p Page[Permission], err error) {
	req, err := ps.client.newRequest(ctx, http.MethodGet, "/api/v1/permission", withPageOptions(po))
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

func (ps PermissionService) AddPermissionToTeam(ctx context.Context, permission Permission, team uuid.UUID) (t Team, err error) {
	req, err := ps.client.newRequest(ctx, http.MethodPost, fmt.Sprintf("/api/v1/permission/%s/team/%s", permission.Name, team.String()))
	if err != nil {
		return
	}

	_, err = ps.client.doRequest(req, &t)
	return
}
func (ps PermissionService) RemovePermissionFromTeam(ctx context.Context, permission Permission, team uuid.UUID) (t Team, err error) {
	req, err := ps.client.newRequest(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/permission/%s/team/%s", permission.Name, team.String()))
	if err != nil {
		return
	}

	_, err = ps.client.doRequest(req, &t)
	return
}
