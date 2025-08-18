package util

import (
	"fmt"
	"net/url"
	"path"
	"strconv"

	"github.com/go-errors/errors"

	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
)

func MakeFindingLink(host string, findingID uint64) string {
	findingLink := fmt.Sprintf(
		"https://%s",
		path.Join(
			host,
			"issues",
			strconv.Itoa(int(findingID)),
		),
	)
	return findingLink
}

func MakeRunLink(host, instanceID string) string {
	runLink := fmt.Sprintf(
		"https://%s",
		path.Join(
			host,
			"runs",
			instanceID,
		),
	)
	return runLink
}

func MakeRepositoryLink(data *ocsffindinginfo.DataSource) (string, error) {
	parsedURL, err := url.Parse(data.GetSourceCodeMetadata().GetRepositoryUrl())
	if err != nil {
		return "", errors.Errorf("invalid repository target link: %w", err)
	}
	if parsedURL.Host != "github.com" {
		return parsedURL.String(), nil
	}

	// A sample GH link looks like:
	// https://github.com/0c34/govwa/blob/master/util/middleware/middleware.go#L1-L1
	var startLine, endLine uint32 = 1, 1
	if data.GetFileFindingLocationData().GetStartLine() > 0 {
		startLine = data.GetFileFindingLocationData().GetStartLine()
	}
	// Defensive approach which leads to fallback to the same start line in case end line is malformed.
	if el := data.GetFileFindingLocationData().GetEndLine(); el > 0 && el > startLine {
		endLine = data.GetFileFindingLocationData().GetEndLine()
	} else {
		endLine = startLine
	}

	res, err := url.JoinPath(
		parsedURL.Host,
		parsedURL.Path,
		"blob",
		data.GetSourceCodeMetadata().GetReference(),
		data.GetUri().GetPath(),
	)
	if err != nil {
		return "", errors.Errorf("invalid repository target link: %w", err)
	}

	return parsedURL.Scheme + "://" + res + fmt.Sprintf("#L%d-L%d", startLine, endLine), nil
}
