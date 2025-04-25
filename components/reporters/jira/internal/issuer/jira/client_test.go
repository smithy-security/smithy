package jira_test

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	gojira "github.com/andygrunwald/go-jira"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/smithy-security/smithy/components/reporters/jira/internal/issuer"
	"github.com/smithy-security/smithy/components/reporters/jira/internal/issuer/jira"
)

func TestClient_BatchCreate(t *testing.T) {
	const (
		testProjectKey       = "TEST"
		testIssueType        = "Task"
		testBaseURL          = "https://jira.example.com"
		testUsername         = "user"
		testPassword         = "pass"
		testMaxRetries       = 3
		testAccountID        = "test-account-id"
		testUserName         = "test-user"
		childTimeoutDuration = 5 * time.Second
	)

	var (
		ctrl             = gomock.NewController(t)
		mockIssueCreator = NewMockIssueCreator(ctrl)
		mockUserGetter   = NewMockUserGetter(ctrl)
		userNotFoundErr  = errors.New("user not found")
		issueCreationErr = errors.New("issue creation failed")
		testUser         = &gojira.User{
			AccountID: testAccountID,
			Name:      testUserName,
		}
		baseURL, _ = url.Parse(testBaseURL)
		config     = jira.Config{
			BaseURL:          baseURL,
			Project:          testProjectKey,
			IssueType:        testIssueType,
			AuthEnabled:      true,
			AuthUsername:     testUsername,
			AuthPassword:     testPassword,
			ClientMaxRetries: testMaxRetries,
		}
	)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	client, err := jira.NewTestClient(mockIssueCreator, mockUserGetter, config)
	require.NoError(t, err)

	createExpectedJiraIssue := func(summary, description string) *gojira.Issue {
		return &gojira.Issue{
			Fields: &gojira.IssueFields{
				Description: description,
				Summary:     summary,
				Type: gojira.IssueType{
					Name: testIssueType,
				},
				Reporter: &gojira.User{
					AccountID: testAccountID,
				},
				Project: gojira.Project{
					Key: testProjectKey,
				},
			},
		}
	}

	t.Run("no issues passed", func(t *testing.T) {
		var ctx, cancel = context.WithTimeout(ctx, childTimeoutDuration)
		defer cancel()

		created, ok, err := client.BatchCreate(ctx, []issuer.Issue{})
		assert.NoError(t, err)
		assert.Equal(t, uint(0), created)
		assert.False(t, ok)
	})

	t.Run("error with GetSelfWithContext", func(t *testing.T) {
		var (
			ctx, cancel = context.WithTimeout(ctx, childTimeoutDuration)
			testIssue   = issuer.Issue{
				Summary:     "Test Issue",
				Description: "Test Description",
			}
		)
		defer cancel()

		mockUserGetter.EXPECT().
			GetSelfWithContext(ctx).
			Return(nil, nil, userNotFoundErr)

		created, ok, err := client.BatchCreate(ctx, []issuer.Issue{testIssue})
		assert.Error(t, err)
		assert.ErrorIs(t, err, userNotFoundErr)
		assert.Equal(t, uint(0), created)
		assert.False(t, ok)
	})

	t.Run("ok success with some errors", func(t *testing.T) {
		var (
			ctx, cancel = context.WithTimeout(ctx, childTimeoutDuration)
			issues      = []issuer.Issue{
				{Summary: "Issue 1", Description: "Description 1"},
				{Summary: "Issue 2", Description: "Description 2"},
				{Summary: "Issue 3", Description: "Description 3"},
			}
			expectedJiraIssue1 = createExpectedJiraIssue("Issue 1", "Description 1")
			expectedJiraIssue2 = createExpectedJiraIssue("Issue 2", "Description 2")
			expectedJiraIssue3 = createExpectedJiraIssue("Issue 3", "Description 3")
		)
		defer cancel()

		gomock.InOrder(
			mockUserGetter.EXPECT().
				GetSelfWithContext(ctx).
				Return(testUser, nil, nil),
			mockIssueCreator.EXPECT().
				CreateWithContext(ctx, expectedJiraIssue1).
				Return(&gojira.Issue{}, nil, nil),
			mockIssueCreator.EXPECT().
				CreateWithContext(ctx, expectedJiraIssue2).
				Return(nil, nil, issueCreationErr),
			mockIssueCreator.EXPECT().
				CreateWithContext(ctx, expectedJiraIssue3).
				Return(&gojira.Issue{}, nil, nil),
		)

		created, ok, err := client.BatchCreate(ctx, issues)
		assert.Error(t, err)
		assert.ErrorIs(t, err, issueCreationErr)
		assert.Equal(t, uint(2), created)
		assert.True(t, ok)
	})

	t.Run("all issues created successfully", func(t *testing.T) {
		var (
			ctx, cancel = context.WithTimeout(ctx, childTimeoutDuration)
			issues      = []issuer.Issue{
				{Summary: "Issue 1", Description: "Description 1"},
				{Summary: "Issue 2", Description: "Description 2"},
			}
			expectedJiraIssue1 = createExpectedJiraIssue("Issue 1", "Description 1")
			expectedJiraIssue2 = createExpectedJiraIssue("Issue 2", "Description 2")
		)
		defer cancel()

		gomock.InOrder(
			mockUserGetter.EXPECT().
				GetSelfWithContext(ctx).
				Return(testUser, nil, nil),
			mockIssueCreator.EXPECT().
				CreateWithContext(ctx, expectedJiraIssue1).
				Return(&gojira.Issue{}, nil, nil),
			mockIssueCreator.EXPECT().
				CreateWithContext(ctx, expectedJiraIssue2).
				Return(&gojira.Issue{}, nil, nil),
		)

		created, ok, err := client.BatchCreate(ctx, issues)
		assert.NoError(t, err)
		assert.Equal(t, uint(2), created)
		assert.True(t, ok)
	})
}

func TestConfig_IsValid(t *testing.T) {
	var (
		validURL, _ = url.Parse("https://jira.example.com")
		emptyURL, _ = url.Parse("")
	)

	for _, tt := range []struct {
		name        string
		config      jira.Config
		expectError bool
		errContains string
	}{
		{
			name: "valid config with auth disabled",
			config: jira.Config{
				BaseURL:     validURL,
				Project:     "TEST",
				AuthEnabled: false,
			},
			expectError: false,
		},
		{
			name: "valid config with auth enabled",
			config: jira.Config{
				BaseURL:      validURL,
				Project:      "TEST",
				AuthEnabled:  true,
				AuthUsername: "user",
				AuthPassword: "pass",
			},
			expectError: false,
		},
		{
			name: "invalid config with empty base URL",
			config: jira.Config{
				BaseURL:     emptyURL,
				Project:     "TEST",
				AuthEnabled: false,
			},
			expectError: true,
			errContains: "base URL is required",
		},
		{
			name: "invalid config with nil base URL",
			config: jira.Config{
				Project:     "TEST",
				AuthEnabled: false,
			},
			expectError: true,
			errContains: "base URL is required",
		},
		{
			name: "invalid config with empty project",
			config: jira.Config{
				BaseURL:     validURL,
				Project:     "",
				AuthEnabled: false,
			},
			expectError: true,
			errContains: "project is required",
		},
		{
			name: "invalid config with auth enabled but missing username",
			config: jira.Config{
				BaseURL:      validURL,
				Project:      "TEST",
				AuthEnabled:  true,
				AuthPassword: "pass",
				AuthUsername: "",
			},
			expectError: true,
			errContains: "auth password and auth username are required",
		},
		{
			name: "invalid config with auth enabled but missing password",
			config: jira.Config{
				BaseURL:      validURL,
				Project:      "TEST",
				AuthEnabled:  true,
				AuthPassword: "",
				AuthUsername: "user",
			},
			expectError: true,
			errContains: "auth password and auth username are required",
		},
		{
			name: "invalid config with auth enabled but missing both",
			config: jira.Config{
				BaseURL:      validURL,
				Project:      "TEST",
				AuthEnabled:  true,
				AuthPassword: "",
				AuthUsername: "",
			},
			expectError: true,
			errContains: "auth password and auth username are required",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.IsValid()
			if !tt.expectError {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			}
		})
	}
}
