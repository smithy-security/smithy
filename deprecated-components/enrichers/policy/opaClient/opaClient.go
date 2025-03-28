package opaclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
)

// Client is the configuration struct for the opa client.
type Client struct {
	RemoteURI  string
	Policy     string
	client     http.Client
	PolicyName string
	PolicyPath string
}

type policyDecisionResult struct {
	Result map[string]bool
}

const (
	// OPAUpdatePolicy is the update policies path in the opa rest api.
	OPAUpdatePolicy = "/v1/policies"
	// OPANamedPolicyDecision is the eval policies path in the opa rest api.
	OPANamedPolicyDecision = "/v1/data"
)

// Bootstrap loads the rego policies found in "$DataDir/policy.rego"
// in the remote opa, name of the remote policy is the value of $DataDir
//
//	if the policy exists it is updated
//
// it is important that the package in the rego document matches the DataDir.
func (c *Client) Bootstrap() error {
	text, err := base64.StdEncoding.DecodeString(c.Policy)
	if err != nil {
		log.Printf("could not decode policy %v", err)
		return err
	}
	c.Policy = string(text)
	pName := regexp.MustCompile(`package (?P<first>\w+)\.(?P<second>\w+)`)
	match := pName.FindStringSubmatch(c.Policy)
	result := make(map[string]string)
	for i, name := range pName.SubexpNames() {
		if i != 0 && name != "" {
			result[name] = match[i]
		}
	}
	c.PolicyPath = result["first"] + "/" + result["second"]
	c.PolicyName = result["second"]

	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPut,
		c.RemoteURI+OPAUpdatePolicy+"/"+c.PolicyName,
		bytes.NewBuffer([]byte(c.Policy)))
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("could not update policy status code: %v \t %v", resp.StatusCode, resp.Body)
	}
	return nil
}

// Decide sends the provided data to the remote OPA server for a named decision
// uses the DataDir value above to match the policy.
func (c *Client) Decide(data []byte) (bool, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, c.RemoteURI+OPANamedPolicyDecision+"/"+c.PolicyPath,
		bytes.NewBuffer(data))
	if err != nil {
		log.Println("Could not create request in order to contact OPA, defaulting to fail err:", err)
		return false, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		log.Println("Could not contact OPA, defaulting to fail err:", err)
		return false, err
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("Could not make decision on policy %s, status code: %v \t %v", c.PolicyPath, resp.StatusCode, resp.Body)
		return false, nil
	}
	if resp.StatusCode == http.StatusOK {
		var policyDecision policyDecisionResult
		if err := json.NewDecoder(resp.Body).Decode(&policyDecision); err != nil {
			log.Println("error decoding decision body", err)
			return false, err
		}
		return policyDecision.Result["allow"], nil
	}
	log.Println("arbitrary failure, this is a bug")
	return false, nil
}
