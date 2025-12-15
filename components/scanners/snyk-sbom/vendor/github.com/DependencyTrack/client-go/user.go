package dtrack

import (
	"context"
	"net/http"
	"net/url"
)

type UserService struct {
	client *Client
}

func (us UserService) Login(ctx context.Context, username, password string) (token string, err error) {
	body := url.Values{}
	body.Set("username", username)
	body.Set("password", password)

	req, err := us.client.newRequest(ctx, http.MethodPost, "/api/v1/user/login", withBody(body))
	if err != nil {
		return
	}

	req.Header.Set("Accept", "*/*")

	_, err = us.client.doRequest(req, &token)
	return
}

func (us UserService) ForceChangePassword(ctx context.Context, username, password, newPassword string) (err error) {
	body := url.Values{}
	body.Set("username", username)
	body.Set("password", password)
	body.Set("newPassword", newPassword)
	body.Set("confirmPassword", newPassword)

	req, err := us.client.newRequest(ctx, http.MethodPost, "/api/v1/user/forceChangePassword", withBody(body))
	if err != nil {
		return
	}

	req.Header.Set("Accept", "*/*")

	_, err = us.client.doRequest(req, nil)
	return
}
