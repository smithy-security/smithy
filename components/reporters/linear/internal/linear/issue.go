package linear

type (
	// Team maps the team info.
	Team struct {
		Name string
		ID   string
	}

	// GetTeamsResponse contains the teams' data.
	GetTeamsResponse struct {
		Teams []Team
	}
	// CreateIssueRequest contains issue request data.
	CreateIssueRequest struct {
		Description string
		Title       string
		Priority    int
	}
	// CreateIssueResponse contains issues' response.
	CreateIssueResponse struct {
		ID  string
		URL string
	}
)
