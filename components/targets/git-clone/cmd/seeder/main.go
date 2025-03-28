package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/smithy-security/pkg/env"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	if err := Main(ctx); err != nil {
		log.Fatal(err)
	}
}

func Main(ctx context.Context) error {
	giteaURL, err := env.GetOrDefault("GITEA_URL", "http://localhost:3000")
	if err != nil {
		return err
	}
	user, err := env.GetOrDefault("GITEA_ADMIN_USER", "gitcloner")
	if err != nil {
		return err
	}
	pass, err := env.GetOrDefault("GITEA_ADMIN_PASSWORD", "smithy1234")
	if err != nil {
		return err
	}
	repo, err := env.GetOrDefault("GIT_REPO_NAME", "testrepo")
	if err != nil {
		return err
	}

	if err := createUser(ctx, giteaURL, user, pass); err != nil {
		return err
	}

	token, err := createToken(ctx, giteaURL, user, pass)
	if err != nil {
		return err
	}

	if err := createRepo(ctx, giteaURL, repo, token); err != nil {
		return err
	}

	return nil
}

func createUser(ctx context.Context, giteaURL string, user, pass string) error {
	createUserURL, err := url.Parse(fmt.Sprintf("%s/user/sign_up", giteaURL))
	if err != nil {
		return fmt.Errorf("failed to parse get token URL: %w", err)
	}

	payload := strings.NewReader(
		fmt.Sprintf(
			`user_name=%s&email=%s@smithy.security&password=%s&retype=%s`,
			user,
			user,
			pass,
			pass,
		),
	)

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		createUserURL.String(),
		payload,
	)
	if err != nil {
		return fmt.Errorf("failed to create new request: %w", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to do request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to do create user request: status %d", resp.StatusCode)
	}

	return nil
}

func createToken(ctx context.Context, giteaURL, user, pass string) (string, error) {
	getTokenURL, err := url.Parse(fmt.Sprintf("%s/api/v1/users/%s/tokens", giteaURL, user))
	if err != nil {
		return "", fmt.Errorf("failed to parse get token URL: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		getTokenURL.String(),
		bytes.NewBuffer([]byte(`{"name": "all-scopes-token", "scopes": ["all"]}`)),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create new request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(user, pass)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to do request: %w", err)
	}

	defer resp.Body.Close()

	var tokenRes map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokenRes); err != nil {
		return "", fmt.Errorf("failed to decode response body: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("failed to do create token request: status %d", resp.StatusCode)
	}

	token, ok := tokenRes["sha1"]
	if !ok {
		return "", fmt.Errorf("failed to find token sha1 in response: %v", tokenRes)
	}

	return token.(string), nil
}

func createRepo(ctx context.Context, giteaURL, repoName, token string) error {
	createRepoURL, err := url.Parse(fmt.Sprintf("%s/api/v1/user/repos", giteaURL))
	if err != nil {
		return fmt.Errorf("failed to parse get token URL: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		createRepoURL.String(),
		bytes.NewBuffer([]byte(fmt.Sprintf(`{"name": "%s", "private": false}`, repoName))),
	)
	if err != nil {
		return fmt.Errorf("failed to create new request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("token %s", token))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to do create repo request: %w", err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to do request: status %d", resp.StatusCode)
	}

	return nil
}
