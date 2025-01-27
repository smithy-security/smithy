package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/components/consumers/defectdojo/types"
)

// Client represents a DefectDojo client.
type Client struct {
	host     string
	apiToken string
	user     string
	UserID   int32
	DojoUser types.DojoUser
}

// DojoTestType is the Defect dojo Enum ID  for "ci/cd test".
const DojoTestType = 119

// DojoClient instantiates the DefectDojo client.
func DojoClient(url, apiToken, user string) (*Client, error) {
	client := &Client{
		host:     url,
		apiToken: apiToken,
		user:     user,
	}
	u, err := client.listUsers()
	if err != nil {
		return nil, err
	}
	var users types.GetUsersResponse
	err = json.Unmarshal(u, &users)
	if err != nil {
		return nil, err
	}
	for _, u := range users.Results {
		if u.Username == user {
			client.UserID = u.ID
			client.DojoUser = u
		}
	}
	return client, nil
}

func (client *Client) listUsers() ([]byte, error) {
	url := fmt.Sprintf("%s/users", client.host)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return client.doRequest(req)
}

// CreateFinding creates a new finding in defectdojo.
func (client *Client) CreateFinding(
	title, description, severity, target, date, numericalSeverity string,
	tags []string,
	testID, line, cwe, foundBy int32,
	falseP, duplicate bool,
	cvssScore float64,
) (types.FindingCreateResponse, error) {
	url := fmt.Sprintf("%s/findings", client.host)
	active := true
	if duplicate {
		active = false
	}
	body := types.FindingCreateRequest{
		Tags:              tags,
		Date:              date,
		Cwe:               cwe,
		Line:              line,
		FilePath:          target,
		Duplicate:         duplicate,
		FalseP:            falseP,
		Active:            active,
		Verified:          false,
		Test:              testID,
		Title:             title,
		Description:       description,
		Severity:          severity,
		NumericalSeverity: numericalSeverity,
		FoundBy:           []int32{foundBy},
	}
	bod, err := json.Marshal(body)
	if err != nil {
		return types.FindingCreateResponse{}, err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(bod))
	if err != nil {
		return types.FindingCreateResponse{}, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("accept", "application/json")
	resp, err := client.doRequest(req)
	if err != nil {
		return types.FindingCreateResponse{}, err
	}
	var result types.FindingCreateResponse
	if err := json.Unmarshal(resp, &result); err != nil {
		return result, errors.Errorf("could not unmarshal finding create resp: %w", err)
	}
	return result, nil
}

// CreateEngagement creates a new engagement in defectdojo.
func (client *Client) CreateEngagement(
	name, scanStartTime string,
	tags []string,
	productID int32,
) (*types.EngagementResponse, error) {
	url := fmt.Sprintf("%s/engagements", client.host)
	body := types.EngagementRequest{
		Name:                      name,
		TargetStart:               scanStartTime,
		TargetEnd:                 scanStartTime,
		Product:                   productID,
		Tags:                      tags,
		DeduplicationOnEngagement: true,
	}
	bod, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(bod))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("accept", "application/json")
	resp, err := client.doRequest(req)
	if err != nil {
		return nil, err
	}
	result := &types.EngagementResponse{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, errors.Errorf("could not unmarshal result '%s': %w", resp, err)
	}
	return result, nil
}

// CreateTest creates a new Test in defectdojo.
func (client *Client) CreateTest(
	scanStartTime, title, description string,
	tags []string,
	engagementID int32,
) (types.TestCreateResponse, error) {
	url := fmt.Sprintf("%s/tests", client.host)
	body := types.TestCreateRequest{
		Engagement:  engagementID,
		Tags:        tags,
		Title:       title,
		Description: description,
		TargetStart: scanStartTime,
		TargetEnd:   scanStartTime,
		TestType:    DojoTestType,
	}
	bod, err := json.Marshal(body)
	if err != nil {
		return types.TestCreateResponse{}, nil
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(bod))
	if err != nil {
		return types.TestCreateResponse{}, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("accept", "application/json")
	resp, err := client.doRequest(req)
	if err != nil {
		return types.TestCreateResponse{}, err
	}
	var result types.TestCreateResponse
	if err := json.Unmarshal(resp, &result); err != nil {
		return result, errors.Errorf("could not unmarshal result '%s': %w", resp, err)
	}
	return result, nil
}

func (client *Client) doRequest(req *http.Request) ([]byte, error) {
	req.Header.Add("User-Agent", "DefectDojo_api/v2")
	req.Header.Add("Authorization", fmt.Sprintf("Token %s", client.apiToken))
	httpClient := &http.Client{CheckRedirect: redirectPostOn301}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	var respErr error
	defer func() { respErr = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, errors.Errorf("status code: %d for url %s and method %s\n body: %s", resp.StatusCode, req.URL, req.Method, body)
	}
	return body, respErr
}

func redirectPostOn301(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}

	lastReq := via[len(via)-1]
	if req.Response.StatusCode == 301 && lastReq.Method == http.MethodPost {
		req.Method = http.MethodPost

		// Get the body of the original request, set here, since req.Body will be nil if a 302 was returned
		if via[0].GetBody != nil {
			var err error
			req.Body, err = via[0].GetBody()
			if err != nil {
				return err
			}
			req.ContentLength = via[0].ContentLength
		}
	}
	return nil
}
