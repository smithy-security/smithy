package dtrack

import (
	"context"
	"fmt"
	"net/http"
)

type EventService struct {
	client *Client
}

type EventToken string

type EventTokenResponse struct {
	Token EventToken `json:"token"`
}

type eventProcessingResponse struct {
	Processing bool `json:"processing"`
}

// IsBeingProcessed checks whether the event associated with a given token is still being processed.
func (es EventService) IsBeingProcessed(ctx context.Context, token EventToken) (bool, error) {
	err := es.client.assertServerVersionAtLeast("4.11.0")
	if err != nil {
		return false, err
	}

	req, err := es.client.newRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/event/token/%s", token))
	if err != nil {
		return false, err
	}

	var processingResponse eventProcessingResponse
	_, err = es.client.doRequest(req, &processingResponse)
	if err != nil {
		return false, err
	}

	return processingResponse.Processing, nil
}
