package opencre

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OpenCREClient represents a client for interacting with OpenCRE.org API
type OpenCREClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// CREResponse represents the response structure from OpenCRE API
type CREResponse struct {
	Data CRENode `json:"data"`
}

type StandardResponse struct {
	Page       int       `json:"page"`
	Standards  []CRENode `json:"standards"`
	TotalPages int       `json:"total_pages"`
}

// CRENode represents a node in the CRE graph
type CRENode struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	DocType     string    `json:"doctype,omitempty"`
	Links       []CRELink `json:"links,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	Section     string    `json:"section,omitempty"`
	SectionID   string    `json:"sectionID,omitempty"`
	Hyperlink   string    `json:"hyperlink,omitempty"`
}

// CRELink represents a link between CRE nodes
type CRELink struct {
	Document CRENode `json:"document"`
	LType    string  `json:"ltype"`
}

// NewOpenCREClient creates a new OpenCRE client
func NewOpenCREClient() *OpenCREClient {
	return &OpenCREClient{
		BaseURL: "https://www.opencre.org/rest/v1",
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// getNode performs a search query against the OpenCRE API
func (c *OpenCREClient) getNode(standardName, sectionID, section, doctype string) (*StandardResponse, error) {
	// Construct the search URL
	searchURL := fmt.Sprintf("%s/%s/%s?sectionID=%s&section=%s",
		c.BaseURL,
		doctype,
		url.QueryEscape(standardName),
		url.QueryEscape(sectionID),
		url.QueryEscape(section),
	)

	// Make the HTTP request
	resp, err := c.HTTPClient.Get(searchURL)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status: %d", resp.StatusCode)
	}

	// Read and parse the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var creResp StandardResponse
	if err := json.Unmarshal(body, &creResp); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	return &creResp, nil
}

// getCRE searches opencre.org for the specified CRE ID and returns the document
func (c *OpenCREClient) getCRE(creID string) (*CREResponse, error) {
	// Construct the CRE-specific search URL
	// Try direct ID lookup first
	searchURL := fmt.Sprintf("%s/id/%s", c.BaseURL, url.QueryEscape(creID))

	// Make the HTTP request
	resp, err := c.HTTPClient.Get(searchURL)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status: %d", resp.StatusCode)
	}

	// Read and parse the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var creResp CREResponse
	if err := json.Unmarshal(body, &creResp); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	// If no data found, return an error
	if creResp.Data.ID == "" {
		return nil, fmt.Errorf("CRE ID '%s' not found", creID)
	}

	return &creResp, nil
}

// findRelatedDocument searches through CRE nodes and their links to find documents of a specific type
// Uses breadth-first search to explore the CRE graph traversing parents and children
func (c *OpenCREClient) findRelatedDocument(cweNumber, docName, doctype string) string {
	// Search for the CWE
	response, err := c.getNode("CWE", cweNumber, "", "standard")
	if err != nil {
		log.Printf("could not get CWE %s err:%s", cweNumber, err)
		return ""
	}

	// Find initial CRE nodes related to our CWE
	var startingCRENodes []CRENode
	for _, node := range response.Standards {
		// Check linked documents
		for _, link := range node.Links {
			// If this is a CRE node, add it to our starting points
			if strings.EqualFold(link.Document.DocType, "CRE") {
				startingCRENodes = append(startingCRENodes, link.Document)
			}
		}

	}

	// If we found CRE nodes, traverse the graph
	if len(startingCRENodes) > 0 {
		return c.traverseCREGraph(startingCRENodes, "standard", docName, make(map[string]bool), 0, 5)
	}

	return ""
}

// traverseCREGraph performs breadth-first search through the CRE graph
func (c *OpenCREClient) traverseCREGraph(creNodes []CRENode, docType, targetName string, visited map[string]bool, depth int, maxDepth int) string {
	if depth > maxDepth {
		return ""
	}

	// Helper function to check if a node matches our criteria
	checkNode := func(node CRENode) string {
		if strings.EqualFold(node.DocType, docType) && strings.EqualFold(node.Name, targetName) {
			if node.ID != "" {
				return node.ID
			}
			if node.SectionID != "" {
				return node.SectionID
			}
			return node.Name
		}
		return ""
	}

	var nextLevelNodes []CRENode

	// Process current level nodes
	for _, creNode := range creNodes {
		// Skip if already visited
		if visited[creNode.ID] {
			continue
		}
		visited[creNode.ID] = true

		// Get full CRE document details
		creResp, err := c.getCRE(creNode.ID)
		if err != nil {
			fmt.Println("error fetching CRE details for node:", creNode.Name, "-", err)
			continue
		}

		// Check all nodes in the CRE response
		node := creResp.Data
		// Check all linked documents
		for _, link := range node.Links {
			if result := checkNode(link.Document); result != "" {
				return result
			}

			// Collect CRE nodes for next level traversal
			if link.Document.DocType == "CRE" && !visited[link.Document.ID] {
				nextLevelNodes = append(nextLevelNodes, link.Document)
			}
		}

		// Also collect any CRE nodes that link to this node
		if node.DocType == "CRE" && !visited[node.ID] {
			nextLevelNodes = append(nextLevelNodes, node)
		}
	}

	// If we have more nodes to explore and haven't exceeded max depth, continue
	if len(nextLevelNodes) > 0 {
		return c.traverseCREGraph(nextLevelNodes, docType, targetName, visited, depth+1, maxDepth)
	}

	return ""
}

// GetASVS accepts a CWE number and searches the graph at opencre.org for the relevant ASVS id and returns it
func (c *OpenCREClient) GetASVS(cwe string) string {
	// Clean the CWE input (remove CWE- prefix if present)
	cweNumber := strings.TrimPrefix(strings.ToUpper(cwe), "CWE-")

	return c.findRelatedDocument(cweNumber, "ASVS", "standard")
}

// GetSAMM accepts a CWE number and searches the graph at opencre.org for the relevant SAMM id and returns it
func (c *OpenCREClient) GetSAMM(cwe string) string {
	// Clean the CWE input (remove CWE- prefix if present)
	cweNumber := strings.TrimPrefix(strings.ToUpper(cwe), "CWE-")

	return c.findRelatedDocument(cweNumber, "SAMM", "standard")
}
