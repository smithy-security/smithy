package dtrack

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type PortfolioMetrics struct {
	FirstOccurrence                      int     `json:"firstOccurrence"`
	LastOccurrence                       int     `json:"lastOccurrence"`
	InheritedRiskScore                   float64 `json:"inheritedRiskScore"`
	Vulnerabilities                      int     `json:"vulnerabilities"`
	VulnerableProjects                   int     `json:"vulnerableProjects"`
	VulnerableComponents                 int     `json:"vulnerableComponents"`
	Projects                             int     `json:"projects"`
	Components                           int     `json:"components"`
	Suppressed                           int     `json:"suppressed"`
	Critical                             int     `json:"critical"`
	High                                 int     `json:"high"`
	Medium                               int     `json:"medium"`
	Low                                  int     `json:"low"`
	Unassigned                           int     `json:"unassigned"`
	FindingsTotal                        int     `json:"findingsTotal"`
	FindingsAudited                      int     `json:"findingsAudited"`
	FindingsUnaudited                    int     `json:"findingsUnaudited"`
	PolicyViolationsTotal                int     `json:"policyViolationsTotal"`
	PolicyViolationsFail                 int     `json:"policyViolationsFail"`
	PolicyViolationsWarn                 int     `json:"policyViolationsWarn"`
	PolicyViolationsInfo                 int     `json:"policyViolationsInfo"`
	PolicyViolationsAudited              int     `json:"policyViolationsAudited"`
	PolicyViolationsUnaudited            int     `json:"policyViolationsUnaudited"`
	PolicyViolationsSecurityTotal        int     `json:"policyViolationsSecurityTotal"`
	PolicyViolationsSecurityAudited      int     `json:"policyViolationsSecurityAudited"`
	PolicyViolationsSecurityUnaudited    int     `json:"policyViolationsSecurityUnaudited"`
	PolicyViolationsLicenseTotal         int     `json:"policyViolationsLicenseTotal"`
	PolicyViolationsLicenseAudited       int     `json:"policyViolationsLicenseAudited"`
	PolicyViolationsLicenseUnaudited     int     `json:"policyViolationsLicenseUnaudited"`
	PolicyViolationsOperationalTotal     int     `json:"policyViolationsOperationalTotal"`
	PolicyViolationsOperationalAudited   int     `json:"policyViolationsOperationalAudited"`
	PolicyViolationsOperationalUnaudited int     `json:"policyViolationsOperationalUnaudited"`
}

type ProjectMetrics struct {
	FirstOccurrence                      int     `json:"firstOccurrence"`
	LastOccurrence                       int     `json:"lastOccurrence"`
	InheritedRiskScore                   float64 `json:"inheritedRiskScore"`
	Vulnerabilities                      int     `json:"vulnerabilities"`
	VulnerableComponents                 int     `json:"vulnerableComponents"`
	Components                           int     `json:"components"`
	Suppressed                           int     `json:"suppressed"`
	Critical                             int     `json:"critical"`
	High                                 int     `json:"high"`
	Medium                               int     `json:"medium"`
	Low                                  int     `json:"low"`
	Unassigned                           int     `json:"unassigned"`
	FindingsTotal                        int     `json:"findingsTotal"`
	FindingsAudited                      int     `json:"findingsAudited"`
	FindingsUnaudited                    int     `json:"findingsUnaudited"`
	PolicyViolationsTotal                int     `json:"policyViolationsTotal"`
	PolicyViolationsFail                 int     `json:"policyViolationsFail"`
	PolicyViolationsWarn                 int     `json:"policyViolationsWarn"`
	PolicyViolationsInfo                 int     `json:"policyViolationsInfo"`
	PolicyViolationsAudited              int     `json:"policyViolationsAudited"`
	PolicyViolationsUnaudited            int     `json:"policyViolationsUnaudited"`
	PolicyViolationsSecurityTotal        int     `json:"policyViolationsSecurityTotal"`
	PolicyViolationsSecurityAudited      int     `json:"policyViolationsSecurityAudited"`
	PolicyViolationsSecurityUnaudited    int     `json:"policyViolationsSecurityUnaudited"`
	PolicyViolationsLicenseTotal         int     `json:"policyViolationsLicenseTotal"`
	PolicyViolationsLicenseAudited       int     `json:"policyViolationsLicenseAudited"`
	PolicyViolationsLicenseUnaudited     int     `json:"policyViolationsLicenseUnaudited"`
	PolicyViolationsOperationalTotal     int     `json:"policyViolationsOperationalTotal"`
	PolicyViolationsOperationalAudited   int     `json:"policyViolationsOperationalAudited"`
	PolicyViolationsOperationalUnaudited int     `json:"policyViolationsOperationalUnaudited"`
}

type MetricsService struct {
	client *Client
}

func (ms MetricsService) LatestPortfolioMetrics(ctx context.Context) (m PortfolioMetrics, err error) {
	req, err := ms.client.newRequest(ctx, http.MethodGet, "/api/v1/metrics/portfolio/current")
	if err != nil {
		return
	}

	_, err = ms.client.doRequest(req, &m)
	return
}

func (ms MetricsService) PortfolioMetricsSince(ctx context.Context, date time.Time) (m []PortfolioMetrics, err error) {
	req, err := ms.client.newRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/metrics/portfolio/since/%s", date.Format("20060102")))
	if err != nil {
		return
	}

	_, err = ms.client.doRequest(req, &m)
	return
}

func (ms MetricsService) PortfolioMetricsSinceDays(ctx context.Context, days uint) (m []PortfolioMetrics, err error) {
	req, err := ms.client.newRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/metrics/portfolio/%d/days", days))
	if err != nil {
		return nil, err
	}

	_, err = ms.client.doRequest(req, &m)
	return
}

func (ms MetricsService) RefreshPortfolioMetrics(ctx context.Context) (err error) {
	req, err := ms.client.newRequest(ctx, http.MethodGet, "/api/v1/metrics/portfolio/refresh")
	if err != nil {
		return
	}

	_, err = ms.client.doRequest(req, nil)
	return
}

func (ms MetricsService) LatestProjectMetrics(ctx context.Context, projectUUID uuid.UUID) (m ProjectMetrics, err error) {
	req, err := ms.client.newRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/metrics/project/%s/current", projectUUID))
	if err != nil {
		return
	}

	_, err = ms.client.doRequest(req, &m)
	return
}

func (ms MetricsService) ProjectMetricsSince(ctx context.Context, projectUUID uuid.UUID, date time.Time) (m []ProjectMetrics, err error) {
	req, err := ms.client.newRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/metrics/project/%s/since/%s", projectUUID, date.Format("20060102")))
	if err != nil {
		return
	}

	_, err = ms.client.doRequest(req, &m)
	return
}

func (ms MetricsService) ProjectMetricsSinceDays(ctx context.Context, projectUUID uuid.UUID, days uint) (m []ProjectMetrics, err error) {
	req, err := ms.client.newRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/metrics/project/%s/days/%d", projectUUID, days))
	if err != nil {
		return nil, err
	}

	_, err = ms.client.doRequest(req, &m)
	return
}

func (ms MetricsService) RefreshProjectMetrics(ctx context.Context, projectUUID uuid.UUID) (err error) {
	req, err := ms.client.newRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/metrics/project/%s/refresh", projectUUID))
	if err != nil {
		return
	}

	_, err = ms.client.doRequest(req, nil)
	return
}
