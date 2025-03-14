package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/go-errors/errors"

	"github.com/smithy-security/smithy/new-components/reporters/defectdojo/internal/types"
)

// Client represents a DefectDojo client.
type Client struct {
	host     string
	apiToken string
	user     string
	UserID   int32
	DojoUser types.DojoUser
}

const DefaultTimeout = 10 * time.Second

// DojoTestType is the Defect dojo Enum ID  for "ci/cd test".
const DojoTestType = 119

// DojoClient instantiates the DefectDojo client.
func DojoClient(ctx context.Context, url, apiToken, user string) (*Client, error) {
	client := &Client{
		host:     url,
		apiToken: apiToken,
		user:     user,
	}
	switch {
	case url == "":
		return nil, errors.New("dojo url is empty")
	case apiToken == "":
		return nil, errors.New("api token is empty")
	case user == "":
		return nil, errors.New("username is empty")
	}
	u, err := client.listUsers(ctx) // equivalent of `ping`, check connectivity and argument correctness
	if err != nil {
		return nil, errors.Errorf("could not list remote users as proof of connection, err: %w", err)
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

func (client *Client) listUsers(ctx context.Context) ([]byte, error) {
	u, err := url.Parse(client.host)
	if err != nil {
		return nil, err
	}
	u.Path = path.Join(u.Path, "users")
	ctx, cancelFunc := context.WithTimeout(ctx, DefaultTimeout)
	defer cancelFunc()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	return client.doRequest(req)
}

// CreateFinding creates a new finding in defectdojo.
func (client *Client) CreateFinding(ctx context.Context, body types.FindingCreateRequest) (types.FindingCreateResponse, error) {
	u, err := url.Parse(client.host)
	if err != nil {
		return types.FindingCreateResponse{}, err
	}
	u.Path = path.Join(u.Path, "findings")

	bod, err := json.Marshal(body)
	if err != nil {
		return types.FindingCreateResponse{}, errors.Errorf("finding create request failed, err: %w", err)
	}
	ctx, cancelFunc := context.WithTimeout(ctx, DefaultTimeout)
	defer cancelFunc()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewBuffer(bod))
	if err != nil {
		return types.FindingCreateResponse{}, err
	}
	resp, err := client.doRequest(req)
	if err != nil {
		return types.FindingCreateResponse{}, err
	}
	var result types.FindingCreateResponse
	if err := json.Unmarshal(resp, &result); err != nil {
		return result, fmt.Errorf("could not unmarshal finding create resp: %w", err)
	}
	return result, nil
}

// CreateEngagement creates a new engagement in defectdojo.
func (client *Client) CreateEngagement(
	ctx context.Context,
	name, scanStartTime string,
	tags []string,
	productID int32,
) (*types.EngagementResponse, error) {
	u, err := url.Parse(client.host)
	if err != nil {
		return nil, err
	}
	u.Path = path.Join(u.Path, "engagements")
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

	ctx, cancelFunc := context.WithTimeout(ctx, DefaultTimeout)
	defer cancelFunc()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewBuffer(bod))
	if err != nil {
		return nil, err
	}
	resp, err := client.doRequest(req)
	if err != nil {
		return nil, err
	}
	result := &types.EngagementResponse{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("could not unmarshal result '%s': %w", resp, err)
	}
	return result, nil
}

// CreateTest creates a new Test in defectdojo.
func (client *Client) CreateTest(
	ctx context.Context,
	scanStartTime, title, description string,
	tags []string,
	engagementID int32,
) (types.TestCreateResponse, error) {
	u, err := url.Parse(client.host)
	if err != nil {
		return types.TestCreateResponse{}, err
	}
	u.Path = path.Join(u.Path, "tests")
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
	ctx, cancelFunc := context.WithTimeout(ctx, DefaultTimeout)
	defer cancelFunc()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewBuffer(bod))
	if err != nil {
		return types.TestCreateResponse{}, err
	}
	resp, err := client.doRequest(req)
	if err != nil {
		return types.TestCreateResponse{}, err
	}
	var result types.TestCreateResponse
	if err := json.Unmarshal(resp, &result); err != nil {
		return result, fmt.Errorf("could not unmarshal result '%s': %w", resp, err)
	}
	return result, nil
}

func (client *Client) doRequest(req *http.Request) ([]byte, error) {
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("accept", "application/json")
	req.Header.Add("User-Agent", "DefectDojo_api/v2")
	req.Header.Add("Authorization", fmt.Sprintf("Token %s", client.apiToken))
	httpClient := &http.Client{CheckRedirect: redirectPostOn301}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("status code: %d for url %s and method %s\n body: %s", resp.StatusCode, req.URL, req.Method, body)
	}
	return body, nil
}

func redirectPostOn301(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if len(via) == 0 {
		return errors.New("redirect array is empty, that's a wrong redirect response")
	}
	lastReq := via[len(via)-1]
	if req.Response.StatusCode == http.StatusMovedPermanently && lastReq.Method == http.MethodPost {
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
