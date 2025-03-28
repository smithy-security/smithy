// Package main of the codeowners enricher
// handles enrichment of individual issues with
// the groups/usernames listed in the github repository
// CODEOWNERS files.
// Owners are matched against the "target" field of the issue
package main

import (
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"strconv"
	"strings"

	"github.com/go-errors/errors"

	apiv1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/deprecated-components/enrichers"
)

const defaultAnnotation = "github-url"

var (
	repoName   string
	ref        string
	orgName    string
	annotation string
)

type fileTarget struct {
	filepath  string
	lineStart string
}

// unused for now
func generateGithubPrURL(owner, repo, filePath, line string, prNumber int64) string {
	sha1Hash := sha1.Sum([]byte(filePath))
	return fmt.Sprintf("https://github.com/%s/%s/pull/%d/files#diff-%sL%s", owner, repo, prNumber, hex.EncodeToString(sha1Hash[:]), line)
}

func generateGithubCommitURL(owner, repo, commitHash, filePath, line string) string {
	return fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s#L%s", owner, repo, commitHash, filePath, line)
}

func splitTarget(target string) (*fileTarget, error) {
	if !strings.HasPrefix(target, "file://") {
		return nil, errors.Errorf("could not extract filePath from target %s", target)
	}
	removeFileProtocol := strings.ReplaceAll(target, "file://", "")
	splitLineNumber := strings.Split(removeFileProtocol, ":")
	if len(splitLineNumber) != 2 {
		return nil, errors.Errorf("could not split line numbers from filepath for target %s", target)
	}
	splitStartingLine := strings.Split(splitLineNumber[1], "-")
	return &fileTarget{
		filepath:  splitLineNumber[0],
		lineStart: splitStartingLine[0],
	}, nil

}

func enrichIssue(i *apiv1.Issue, owner, repoName, ref string) (*apiv1.EnrichedIssue, error) {
	enrichedIssue := apiv1.EnrichedIssue{
		RawIssue: i,
	}
	annotations := map[string]string{}
	fileTarget, err := splitTarget(i.Target)
	if err != nil { // could not read the target, we still need to propagate the issue so just return it
		return &enrichedIssue, err
	}
	url := ""
	prNum, err := strconv.ParseInt(ref, 10, 64) // if the reference is an integer then we're looking for a pull request
	if err == nil {
		url = generateGithubPrURL(owner, repoName, fileTarget.filepath, fileTarget.lineStart, prNum)
	} else { // otherwise the reference is a regular commit hash or branch
		url = generateGithubCommitURL(owner, repoName, ref, fileTarget.filepath, fileTarget.lineStart)
	}
	annotations[defaultAnnotation] = url
	enrichedIssue.Annotations = annotations
	return &enrichedIssue, nil
}

func enrichIssues(issues []*apiv1.Issue) []*apiv1.EnrichedIssue {
	enrichedIssues := []*apiv1.EnrichedIssue{}
	for _, i := range issues {
		eI, err := enrichIssue(i, orgName, repoName, ref)
		if err != nil {
			slog.Error(err.Error())
		}
		enrichedIssues = append(enrichedIssues, eI)
	}
	return enrichedIssues
}

func run() error {
	res, err := enrichers.LoadData()
	if err != nil {
		return err
	}
	for _, r := range res {
		enrichedIssues := enrichIssues(r.GetIssues())
		err := enrichers.WriteData(&apiv1.EnrichedLaunchToolResponse{
			OriginalResults: r,
			Issues:          enrichedIssues,
		}, defaultAnnotation)
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	flag.StringVar(&orgName, "orgName", enrichers.LookupEnvOrString("ORG_NAME", ""), "name of the repository owner, most often the organization names")
	flag.StringVar(&ref, "ref", enrichers.LookupEnvOrString("REFERENCE", ""), "either pull request number or commit hash")
	flag.StringVar(&repoName, "repoName", enrichers.LookupEnvOrString("REPO_NAME", ""), "the name of the repository")

	if err := enrichers.ParseFlags(); err != nil {
		log.Fatal(err)
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
