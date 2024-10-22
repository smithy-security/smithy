package main

import (
	"bytes"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"
	"time"

	"text/template"

	"github.com/go-errors/errors"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

type changelog struct {
	Tag        string
	TagMessage string
	Messages   []string
	Timestamp  string
}

type annotatedTag struct {
	Name        string
	Message     string
	Timestamp   string
	previousTag *annotatedTag
}

var (
	//go:embed changelog.tmpl.md
	defaultTemplate         string
	errNoAnnotatedTags      = errors.Errorf("no annotated tags found")
	errFailedToGetHead      = errors.Errorf("failed to get HEAD")
	signalingErrCommitFound = errors.Errorf("reached the tag commit, stop iterating")
)

// getLatestAnnotatedTag retrieves the tag name and the message of the latest annotated tag.
func getLatestAnnotatedTag(repo *git.Repository) (annotatedTag, error) {
	// Get the tag references from the repository
	tags, err := repo.Tags()
	if err != nil {
		return annotatedTag{}, errors.Errorf("failed to get tags: %v", err)
	}

	var latestTagObject *object.Tag
	var previousTagObject *object.Tag
	// Iterate through the tags to find the latest annotated tag
	err = tags.ForEach(func(tagRef *plumbing.Reference) error {
		// Try to get the tag object (only annotated tags have this)
		tagObj, err := repo.TagObject(tagRef.Hash())
		if err != nil {
			// Skip lightweight tags, which do not have messages
			return nil
		}

		// Compare tag creation dates to find the latest tag
		if latestTagObject == nil || tagObj.Tagger.When.After(latestTagObject.Tagger.When) {
			previousTagObject = latestTagObject
			latestTagObject = tagObj
		}
		return nil
	})
	if err != nil {
		return annotatedTag{}, err
	}

	if latestTagObject == nil {
		return annotatedTag{}, errNoAnnotatedTags
	}

	var previousTag annotatedTag
	if previousTagObject != nil {
		previousTag = annotatedTag{
			Name:      strings.TrimSpace(previousTagObject.Name),
			Message:   strings.TrimSpace(previousTagObject.Message),
			Timestamp: strings.TrimSpace(previousTagObject.Tagger.When.Format(time.RFC3339)),
		}
	}

	annotatedTag := annotatedTag{
		Name:        strings.TrimSpace(latestTagObject.Name),
		Message:     strings.TrimSpace(latestTagObject.Message),
		Timestamp:   strings.TrimSpace(latestTagObject.Tagger.When.Format(time.RFC3339)),
		previousTag: &previousTag,
	}
	return annotatedTag, nil
}

func getCommitMessagesUntilHead(fromTagName string, repo *git.Repository) ([]string, error) {
	found := false
	rangeMsgs := strings.TrimSpace(fromTagName)

	// Resolve HEAD reference
	headRef, err := repo.Head()
	if err != nil {
		return nil, errFailedToGetHead
	}

	// Get the tag's commit hash
	tagRef, err := repo.ResolveRevision(plumbing.Revision(rangeMsgs))
	if err != nil {
		return nil, errors.Errorf("failed to resolve tag reference: %v", err)
	}

	// Get the commit iterator between the latest tag and HEAD
	commitIter, err := repo.Log(&git.LogOptions{
		From:  headRef.Hash(),
		Order: git.LogOrderCommitterTime,
	})
	if err != nil {
		return nil, errors.Errorf("failed to get commit logs: %v", err)
	}

	var logOutput []string
	err = commitIter.ForEach(func(c *object.Commit) error {
		// Format the commit message: "commit message title"
		msg := strings.Split(c.Message, "\n\n")
		logOutput = append(logOutput, msg[0])

		// Stop when the commit hash matches the tag commit
		if c.Hash.String() == tagRef.String() {
			found = true
			return signalingErrCommitFound
		}
		return nil
	})

	if err != nil && !errors.Is(err, signalingErrCommitFound) {
		return nil, err
	}

	if !found { // edge case where there are tags but the commits for those tags are not in the branch
		return nil, errors.Errorf("did not find the tag reference for tag %s", fromTagName)
	}

	return logOutput, nil
}

// generateChangelog generates a changelog between the latest tag and HEAD.
func generateChangelog(repo *git.Repository, newTag annotatedTag, changelogTemplate string) (string, error) {
	tag, err := getLatestAnnotatedTag(repo)
	if err != nil {
		return "", err
	}
	slog.Info("the latest annotated tag is", slog.String("tag", tag.Name))

	commitMsgs, err := getCommitMessagesUntilHead(tag.Name, repo)
	if err != nil {
		return "", err
	}

	if len(commitMsgs) == 1 { // HEAD has 1 commit since the last tag, the tagged one, edge case where we are on HEAD
		slog.Info("Head is on the latest annotated tag, creating a changelog between the previous tag and head", "the second to last annotated tag is", slog.String("tag", tag.previousTag.Name))
		commitMsgs, err = getCommitMessagesUntilHead(tag.previousTag.Name, repo)
		if err != nil {
			return "", err
		}
		newTag = tag
	}

	slog.Info("working with", slog.Int("commits", len(commitMsgs)))
	change := changelog{
		Tag:        newTag.Name,
		TagMessage: newTag.Message,
		Messages:   commitMsgs,
	}

	// Format the changelog
	tmpl, err := template.New("changelog").Parse(changelogTemplate)
	if err != nil {
		return "", err
	}
	buf := new(bytes.Buffer)
	tmpl.Execute(buf, change)

	return buf.String(), nil
}

type conf struct {
	RepoPath          string
	ChangelogTmplPath string
	NewTagName        string
	NewTagMessage     string
}

var config = conf{}

func main() {
	flag.StringVar(&config.RepoPath, "repo-path", "", "path to the repository you want to generate a changelog for")
	flag.StringVar(&config.ChangelogTmplPath, "changelog-template-path", "", "path to the go-template you want to use for templating your changelog")
	flag.StringVar(&config.NewTagName, "new-tag-name", "", "name of the new tag, usually a semver like v1.2.3")
	flag.StringVar(&config.NewTagMessage, "new-tag-message", "", "message of the new tag, usually a summary of the changes")
	flag.Parse()
	repo, err := git.PlainOpen(config.RepoPath)
	if err != nil {
		log.Fatalf("Failed to open repository '%s': %v", config.RepoPath, err)
	}

	changelogTemplate := defaultTemplate
	if config.ChangelogTmplPath != "" {
		changelogBytes, err := os.ReadFile(config.ChangelogTmplPath)
		if err != nil {
			log.Fatal(err)
		}

		changelogTemplate = string(changelogBytes)
	}
	changelog, err := generateChangelog(repo, annotatedTag{Name: config.NewTagName, Message: config.NewTagMessage}, changelogTemplate)
	if err != nil {
		log.Fatalf("Error generating changelog: %v", err)
	}

	fmt.Println(changelog)
}
