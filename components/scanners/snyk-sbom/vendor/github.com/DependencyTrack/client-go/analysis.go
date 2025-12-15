package dtrack

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

type AnalysisJustification string

const (
	AnalysisJustificationCodeNotPresent               AnalysisJustification = "CODE_NOT_PRESENT"
	AnalysisJustificationCodeNotReachable             AnalysisJustification = "CODE_NOT_REACHABLE"
	AnalysisJustificationNotSet                       AnalysisJustification = "NOT_SET"
	AnalysisJustificationProtectedAtPerimeter         AnalysisJustification = "PROTECTED_AT_PERIMETER"
	AnalysisJustificationProtectedAtRuntime           AnalysisJustification = "PROTECTED_AT_RUNTIME"
	AnalysisJustificationProtectedByCompiler          AnalysisJustification = "PROTECTED_BY_COMPILER"
	AnalysisJustificationProtectedByMitigatingControl AnalysisJustification = "PROTECTED_BY_MITIGATING_CONTROL"
	AnalysisJustificationRequiresConfiguration        AnalysisJustification = "REQUIRES_CONFIGURATION"
	AnalysisJustificationRequiresDependency           AnalysisJustification = "REQUIRES_DEPENDENCY"
	AnalysisJustificationRequiresEnvironment          AnalysisJustification = "REQUIRES_ENVIRONMENT"
)

type AnalysisResponse string

const (
	AnalysisResponseCanNotFix           AnalysisResponse = "CAN_NOT_FIX"
	AnalysisResponseNotSet              AnalysisResponse = "NOT_SET"
	AnalysisResponseRollback            AnalysisResponse = "ROLLBACK"
	AnalysisResponseUpdate              AnalysisResponse = "UPDATE"
	AnalysisResponseWillNotFix          AnalysisResponse = "WILL_NOT_FIX"
	AnalysisResponseWorkaroundAvailable AnalysisResponse = "WORKAROUND_AVAILABLE"
)

type AnalysisState string

const (
	AnalysisStateExploitable   AnalysisState = "EXPLOITABLE"
	AnalysisStateFalsePositive AnalysisState = "FALSE_POSITIVE"
	AnalysisStateInTriage      AnalysisState = "IN_TRIAGE"
	AnalysisStateNotAffected   AnalysisState = "NOT_AFFECTED"
	AnalysisStateNotSet        AnalysisState = "NOT_SET"
	AnalysisStateResolved      AnalysisState = "RESOLVED"
)

type Analysis struct {
	Comments      []AnalysisComment     `json:"analysisComments"`
	State         AnalysisState         `json:"analysisState"`
	Justification AnalysisJustification `json:"analysisJustification"`
	Response      AnalysisResponse      `json:"analysisResponse"`
	Details       string                `json:"analysisDetails"`
	Suppressed    bool                  `json:"isSuppressed"`
}

type AnalysisComment struct {
	Comment   string `json:"comment"`
	Commenter string `json:"commenter"`
	Timestamp int    `json:"timestamp"`
}

type AnalysisRequest struct {
	Component     uuid.UUID             `json:"component"`
	Project       uuid.UUID             `json:"project"`
	Vulnerability uuid.UUID             `json:"vulnerability"`
	Comment       string                `json:"comment,omitempty"`
	State         AnalysisState         `json:"analysisState,omitempty"`
	Justification AnalysisJustification `json:"analysisJustification,omitempty"`
	Response      AnalysisResponse      `json:"analysisResponse,omitempty"`
	Details       string                `json:"analysisDetails,omitempty"`
	Suppressed    *bool                 `json:"isSuppressed,omitempty"`
}

type AnalysisService struct {
	client *Client
}

func (as AnalysisService) Get(ctx context.Context, component, project, vulnerability uuid.UUID) (a Analysis, err error) {
	params := map[string]string{
		"component":     component.String(),
		"project":       project.String(),
		"vulnerability": vulnerability.String(),
	}

	req, err := as.client.newRequest(ctx, http.MethodGet, "/api/v1/analysis", withParams(params))
	if err != nil {
		return
	}

	_, err = as.client.doRequest(req, &a)
	return
}

func (as AnalysisService) Create(ctx context.Context, analysisReq AnalysisRequest) (a Analysis, err error) {
	req, err := as.client.newRequest(ctx, http.MethodPut, "/api/v1/analysis", withBody(analysisReq))
	if err != nil {
		return
	}

	_, err = as.client.doRequest(req, &a)
	return
}
