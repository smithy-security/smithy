package dtrack

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

type PolicyCondition struct {
	UUID     uuid.UUID               `json:"uuid,omitempty"`
	Policy   *Policy                 `json:"policy,omitempty"`
	Operator PolicyConditionOperator `json:"operator"`
	Subject  PolicyConditionSubject  `json:"subject"`
	Value    string                  `json:"value"`
}

type PolicyConditionService struct {
	client *Client
}

type PolicyConditionOperator string

const (
	PolicyConditionOperatorIs                        PolicyConditionOperator = "IS"
	PolicyConditionOperatorIsNot                     PolicyConditionOperator = "IS_NOT"
	PolicyConditionOperatorMatches                   PolicyConditionOperator = "MATCHES"
	PolicyConditionOperatorNoMatch                   PolicyConditionOperator = "NO_MATCH"
	PolicyConditionOperatorNumericGreaterThan        PolicyConditionOperator = "NUMERIC_GREATER_THAN"
	PolicyConditionOperatorNumericLessThan           PolicyConditionOperator = "NUMERIC_LESS_THAN"
	PolicyConditionOperatorNumericEqual              PolicyConditionOperator = "NUMERIC_EQUAL"
	PolicyConditionOperatorNumericNotEqual           PolicyConditionOperator = "NUMERIC_NOT_EQUAL"
	PolicyConditionOperatorNumericGreaterThanOrEqual PolicyConditionOperator = "NUMERIC_GREATER_THAN_OR_EQUAL"
	PolicyConditionOperatorNumericLesserThanOrEqual  PolicyConditionOperator = "NUMERIC_LESSER_THAN_OR_EQUAL"
	PolicyConditionOperatorContainsAll               PolicyConditionOperator = "CONTAINS_ALL"
	PolicyConditionOperatorContainsAny               PolicyConditionOperator = "CONTAINS_ANY"
)

type PolicyConditionSubject string

const (
	PolicyConditionSubjectAge             PolicyConditionSubject = "AGE"
	PolicyConditionSubjectCoordinates     PolicyConditionSubject = "COORDINATES"
	PolicyConditionSubjectCPE             PolicyConditionSubject = "CPE"
	PolicyConditionSubjectLicense         PolicyConditionSubject = "LICENSE"
	PolicyConditionSubjectLicenseGroup    PolicyConditionSubject = "LICENSE_GROUP"
	PolicyConditionSubjectPackageURL      PolicyConditionSubject = "PACKAGE_URL"
	PolicyConditionSubjectSeverity        PolicyConditionSubject = "SEVERITY"
	PolicyConditionSubjectSWIDTagID       PolicyConditionSubject = "SWID_TAGID"
	PolicyConditionSubjectVersion         PolicyConditionSubject = "VERSION"
	PolicyConditionSubjectComponentHash   PolicyConditionSubject = "COMPONENT_HASH"
	PolicyConditionSubjectCWE             PolicyConditionSubject = "CWE"
	PolicyConditionSubjectVulnerabilityID PolicyConditionSubject = "VULNERABILITY_ID"
)

func (pcs PolicyConditionService) Create(ctx context.Context, policyUUID uuid.UUID, policyCondition PolicyCondition) (p PolicyCondition, err error) {
	req, err := pcs.client.newRequest(ctx, http.MethodPut, fmt.Sprintf("/api/v1/policy/%s/condition", policyUUID), withBody(policyCondition))
	if err != nil {
		return
	}

	_, err = pcs.client.doRequest(req, &p)
	return
}

func (pcs PolicyConditionService) Update(ctx context.Context, policyCondition PolicyCondition) (p PolicyCondition, err error) {
	req, err := pcs.client.newRequest(ctx, http.MethodPost, "/api/v1/policy/condition", withBody(policyCondition))
	if err != nil {
		return
	}

	_, err = pcs.client.doRequest(req, &p)
	return
}

func (pcs PolicyConditionService) Delete(ctx context.Context, policyConditionUUID uuid.UUID) (err error) {
	req, err := pcs.client.newRequest(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/policy/condition/%s", policyConditionUUID))
	if err != nil {
		return
	}

	_, err = pcs.client.doRequest(req, nil)
	return
}
