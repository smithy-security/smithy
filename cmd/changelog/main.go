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

	"github.com/blang/semver"
	"github.com/go-errors/errors"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

type changelog struct {
	Tag        string
	TagMessage string
	Messages   []commitMessage
	Timestamp  string
}

type commitMessage struct {
	Message   string
	Timestamp string
}
type annotatedTag struct {
	Name      string
	Message   string
	Timestamp string
}

type stringList []string

type conf struct {
	RepoPath          string
	ChangelogTmplPath string
	CurrentTagName    string
	Patch             bool
	Minor             bool
	Major             bool
	Message           string
	Build             stringList
	PrintChangelog    bool
}

var (
	//go:embed changelog.tmpl.md
	defaultTemplate         string
	errNoAnnotatedTags      = errors.Errorf("no annotated tags found")
	errFailedToGetHead      = errors.Errorf("failed to get HEAD")
	errHeadOnLatestTag      = errors.Errorf("head is already on the latest tag")
	signalingErrCommitFound = errors.Errorf("reached the tag commit, stop iterating")
	config                  = conf{}
)

func (s stringList) String() string {
	return strings.Join(s, ",")
}

func (s *stringList) Set(value string) error {
	*s = strings.Split(value, ",")
	return nil
}

// getLatestAnnotatedTag retrieves the tag name and the message of the latest annotated tag.
func getAnnotatedTag(repo *git.Repository, tag string) (annotatedTag, error) {
	// Get the tag references from the repository
	tags, err := repo.Tags()
	if err != nil {
		return annotatedTag{}, errors.Errorf("failed to get tags: %v", err)
	}

	var targetTag *object.Tag
	// Iterate through the tags to find the latest annotated tag
	err = tags.ForEach(func(tagRef *plumbing.Reference) error {
		// Try to get the tag object (only annotated tags have this)
		tagObj, err := repo.TagObject(tagRef.Hash())
		if err != nil {
			// Skip lightweight tags, which do not have messages
			return nil
		}
		if tagObj.Name == tag {
			targetTag = tagObj
		}
		return nil
	})
	if err != nil {
		return annotatedTag{}, err
	}

	if targetTag == nil {
		return annotatedTag{}, errNoAnnotatedTags
	}

	annotatedTag := annotatedTag{
		Name:      strings.TrimSpace(targetTag.Name),
		Message:   strings.TrimSpace(targetTag.Message),
		Timestamp: strings.TrimSpace(targetTag.Tagger.When.Format(time.RFC3339)),
	}
	return annotatedTag, nil
}

// getCommitMessagesUntilHead retrieves a list of commit messages between the "fromTagName" and current HEAD
func getCommitMessagesUntilHead(fromTagName string, repo *git.Repository) ([]commitMessage, error) {
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

	// Get the commit iterator between the latest tag and target tag
	commitIter, err := repo.Log(&git.LogOptions{
		From:  headRef.Hash(),
		Order: git.LogOrderCommitterTime,
	})
	if err != nil {
		return nil, errors.Errorf("failed to get commit logs: %w", err)
	}

	var logOutput []commitMessage
	err = commitIter.ForEach(func(c *object.Commit) error {
		msg := strings.Split(c.Message, "\n\n")
		logOutput = append(logOutput, commitMessage{Message: msg[0], Timestamp: c.Author.When.Format(time.RFC3339)})

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

// generateChangelog generates a changelog between the provided tag and HEAD.
func generateChangelog(repo *git.Repository, tagFrom, newTag, changelogTemplate, changelogMessage string) (string, error) {
	tagObjFrom, err := getAnnotatedTag(repo, tagFrom)
	if err != nil {
		return "", fmt.Errorf("could not retrieve annotated tag %s, err:%w", tagFrom, err)
	}
	slog.Info("the latest annotated tag is", slog.String("tag", tagObjFrom.Name))

	commitMsgs, err := getCommitMessagesUntilHead(tagObjFrom.Name, repo)
	if err != nil {
		return "", fmt.Errorf("could not get commit messages from tag %s to HEAD, err:%w", tagObjFrom.Name, err)
	}

	if len(commitMsgs) == 1 { // HEAD has 1 commit since the last tag, the tagged one, edge case where we are on HEAD
		slog.Info("Head is on the latest annotated tag, changelog will be empty (did you forget to add commits?)")
		return "", errHeadOnLatestTag
	}

	slog.Info("working with", slog.Int("commits", len(commitMsgs)))
	change := changelog{
		Tag:        newTag,
		TagMessage: changelogMessage,
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

// calculateNewTag will return a valid semver tag based on the configuration provided (depending which of the major/minor/patch are true)
func calculateNewTag(config conf) (string, error) {
	currentVersion, err := semver.ParseTolerant(config.CurrentTagName)
	if err != nil {
		slog.Error("provided semver is not valid", slog.String("semver", config.CurrentTagName))
		return "", err
	}
	tagScore := 0
	if config.Major {
		tagScore += 1
		currentVersion.Major++
	}
	if config.Minor {
		tagScore += 1
		currentVersion.Minor++
	}
	if config.Patch {
		tagScore += 1
		currentVersion.Patch++
	}
	if tagScore != 1 {
		return "", fmt.Errorf("you need to provide exactly one argument from '-patch', '-minor', '-major'")
	}
	currentVersion.Build = config.Build
	return currentVersion.String(), nil
}

// applyTag applies the 'newTagName' tag to the current HEAD of the repository provided and sets the message to 'newTagMessage'
func applyTag(repo *git.Repository, newTagName, newTagMessage string) error {
	// Get the HEAD reference (the latest commit on the current branch)
	head, err := repo.Head()
	if err != nil {
		return fmt.Errorf("failed to get HEAD reference: %w", err)
	}

	// Create a new annotated tag
	tagRef, err := repo.CreateTag(newTagName, head.Hash(), &git.CreateTagOptions{
		Message: newTagMessage,
		Tagger: &object.Signature{
			Name:  "",
			Email: "",
			When:  time.Now(),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create tag: %w", err)
	}

	fmt.Printf("Tag %s created at %s\n", newTagName, tagRef.Hash().String())
	return nil
}

func main() {
	flag.StringVar(&config.RepoPath, "repo-path", "", "path to the repository you want to generate a changelog for")
	flag.StringVar(&config.ChangelogTmplPath, "changelog-template-path", "", "path to the go-template you want to use for templating your changelog")
	flag.StringVar(&config.CurrentTagName, "current-tag", "", "name of the current latest tag, usually a semver like v1.2.3")
	flag.BoolVar(&config.Minor, "minor", false, "create a new minor version")
	flag.BoolVar(&config.Major, "major", false, "create a new major version")
	flag.BoolVar(&config.Patch, "patch", false, "create a new patch version")
	flag.Var(&config.Build, "build", "comma separated build specific strings for the semver")
	flag.StringVar(&config.Message, "message", "", "message to add to the new tag")
	flag.BoolVar(&config.PrintChangelog, "print", false, "do not release, just print the changelog between current-tag and HEAD")

	flag.Parse()
	repo, err := git.PlainOpen(config.RepoPath)
	if err != nil {
		log.Fatalf("Failed to open repository '%s': %v", config.RepoPath, err)
	}

	if config.CurrentTagName == "" {
		log.Fatal("current-tag is empty")
	}

	changelogTemplate := defaultTemplate
	if config.ChangelogTmplPath != "" {
		changelogBytes, err := os.ReadFile(config.ChangelogTmplPath)
		if err != nil {
			log.Fatal(err)
		}
		changelogTemplate = string(changelogBytes)
	}

	var newTag string
	if !config.PrintChangelog {
		nt, err := calculateNewTag(config)
		if err != nil {
			log.Fatal(err)
		}
		newTag = nt
	}

	changelog, err := generateChangelog(repo, config.CurrentTagName, newTag, changelogTemplate, config.Message)
	if err != nil {
		log.Fatalf("Error generating changelog: %v", err)
	}

	if !config.PrintChangelog {
		if err = applyTag(repo, newTag, changelog); err != nil {
			log.Fatalf("Error generating changelog: %v", err)
		}
	}

	fmt.Println(changelog)
}
