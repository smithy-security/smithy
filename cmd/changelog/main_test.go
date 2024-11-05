package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

type gitObj struct {
	msg          string
	name         string
	timestamp    string
	tagCommitNum int // for tags only, tag specific commit hash
}

// createCommit creates a new commit in the repository.
func createCommit(repo *git.Repository, workspace, message, timestamp string) (plumbing.Hash, error) {
	// Get the working tree
	worktree, err := repo.Worktree()
	if err != nil {
		return plumbing.ZeroHash, err
	}

	// Write a dummy file (if you're working with a non-bare repository)
	filename := "dummyfile.txt"
	err = os.WriteFile(filepath.Join(workspace, filename), []byte("Hello, world!"), 0644)
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("failed to write dummy file: %v", err)
	}

	// Add the file to the staging area
	_, err = worktree.Add(filename)
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("failed to add file: %v", err)
	}

	when, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return plumbing.ZeroHash, err
	}
	// Commit the changes
	commitHash, err := worktree.Commit(message, &git.CommitOptions{
		Author: &object.Signature{
			Name:  "foobar",
			Email: "foobar@example.com",
			When:  when,
		},
	})
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("failed to create commit: %v", err)
	}

	return commitHash, nil
}

// createAnnotatedTag creates an annotated tag for the given commit.
func createAnnotatedTag(repo *git.Repository, commitHash plumbing.Hash, tagName, tagMessage, tagTimestamp string) (*plumbing.Reference, error) {
	when, err := time.Parse(time.RFC3339, tagTimestamp)
	if err != nil {
		return nil, err
	}
	// Create the annotated tag
	tagHash, err := repo.CreateTag(tagName, commitHash, &git.CreateTagOptions{
		Message: tagMessage,
		Tagger: &object.Signature{
			Name:  "Jane Doe",
			Email: "janedoe@example.com",
			When:  when,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create annotated tag: %v", err)
	}

	return tagHash, nil
}

// createInMemoryRepo creates an empty Git repository in memory.
func mustCreateRepo(workspace string, commits, tags []gitObj) *git.Repository {
	repo, err := git.PlainInit(workspace, false)
	if err != nil {
		panic(err)
	}

	commitHashes := make([]plumbing.Hash, 0, len(commits))
	for _, c := range commits {
		cHash, err := createCommit(repo, workspace, c.msg, c.timestamp)
		if err != nil {
			panic(err)
		}
		commitHashes = append(commitHashes, cHash)
	}

	for i, t := range tags {
		commitNum := i % len(commitHashes)
		if t.tagCommitNum != 0 {
			commitNum = t.tagCommitNum
		}
		if _, err := createAnnotatedTag(repo,
			commitHashes[commitNum],
			t.name, t.msg, t.timestamp); err != nil {
			panic(err)
		}
	}
	return repo
}

func Test_getLatestAnnotatedTag(t *testing.T) {
	workspace := ""
	dummyTimestamp := "2023-01-19T18:09:06Z"

	type args struct {
		repo func() *git.Repository
	}
	tests := []struct {
		name    string
		args    args
		want    annotatedTag
		wantErr error
	}{
		{
			name: "no tags, empty repo",
			args: args{
				repo: func() *git.Repository {
					workspace := t.TempDir()
					return mustCreateRepo(workspace, []gitObj{}, []gitObj{})
				},
			},
			want:    annotatedTag{},
			wantErr: errNoAnnotatedTags,
		},
		{
			name: "1 tag",
			args: args{
				repo: func() *git.Repository {
					os.RemoveAll(workspace)
					workspace = t.TempDir()
					return mustCreateRepo(workspace,
						[]gitObj{
							{msg: "foo", timestamp: dummyTimestamp},
							{msg: "bar", timestamp: dummyTimestamp},
						},
						[]gitObj{
							{
								name:      "v0.0",
								msg:       "init",
								timestamp: dummyTimestamp,
							},
						})
				},
			},
			want: annotatedTag{
				Name:      "v0.0",
				Message:   "init",
				Timestamp: dummyTimestamp,
			},
			wantErr: nil,
		},
		{
			name: "2 tags",
			args: args{
				repo: func() *git.Repository {
					os.RemoveAll(workspace)
					workspace = t.TempDir()
					return mustCreateRepo(workspace,
						[]gitObj{
							{msg: "foo", timestamp: dummyTimestamp},
							{msg: "bar", timestamp: dummyTimestamp},
							{msg: "baz", timestamp: dummyTimestamp},
						},
						[]gitObj{
							{
								name:      "v0.0",
								msg:       "init",
								timestamp: dummyTimestamp,
							},
							{
								name:      "v0.0.1",
								msg:       "feature1",
								timestamp: "2024-01-19T18:09:06Z",
							},
						})

				},
			},
			want: annotatedTag{
				Name:      "v0.0.1",
				Message:   "feature1",
				Timestamp: "2024-01-19T18:09:06Z",
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getLatestAnnotatedTag(tt.args.repo())
			if (err != nil) && err != tt.wantErr {
				t.Errorf("getLatestAnnotatedTag() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getLatestAnnotatedTag() = %v, want %v", got, tt.want)
			}
		})
	}
	os.RemoveAll(workspace)
}

func Test_getCommitMessagesUntilHead(t *testing.T) {
	workspace := ""
	dummyTimestamp := "2023-01-19T18:09:06Z"

	type args struct {
		repo func() *git.Repository
		from string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr error
	}{
		{
			name: "empty repo",
			args: args{
				repo: func() *git.Repository {
					workspace := t.TempDir()
					return mustCreateRepo(workspace, []gitObj{}, []gitObj{})
				},
				from: "",
			},
			want:    nil,
			wantErr: errFailedToGetHead,
		},
		{
			name: "2 commits",
			args: args{
				repo: func() *git.Repository {
					os.RemoveAll(workspace)
					workspace = t.TempDir()
					return mustCreateRepo(workspace,
						[]gitObj{
							{msg: "foo", timestamp: dummyTimestamp},
							{msg: "bar", timestamp: dummyTimestamp},
						},
						[]gitObj{})
				},
				from: "HEAD~1",
			},
			want:    []string{"bar", "foo"},
			wantErr: nil,
		},
		{
			name: "3 commits, from is HEAD-1",
			args: args{
				repo: func() *git.Repository {
					os.RemoveAll(workspace)
					workspace = t.TempDir()
					return mustCreateRepo(workspace,
						[]gitObj{
							{msg: "foobar", timestamp: dummyTimestamp},
							{msg: "foo", timestamp: dummyTimestamp},
							{msg: "bar", timestamp: dummyTimestamp},
							{msg: "baz", timestamp: dummyTimestamp},
						}, []gitObj{})

				},
				from: "HEAD~2",
			},

			want:    []string{"baz", "bar", "foo"},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getCommitMessagesUntilHead(tt.args.from, tt.args.repo())
			if (err != nil) && err != tt.wantErr {
				t.Errorf("getCommitMessagesUntilHead() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getCommitMessagesUntilHead() = %v, want %v", got, tt.want)
			}
		})
	}
	os.RemoveAll(workspace)
}

func Test_generateChangelog(t *testing.T) {
	workspace := ""
	dummyTimestamp := "2023-01-19T18:09:06Z"

	type args struct {
		repo     func() *git.Repository
		template string
		newTag   annotatedTag
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr error
	}{
		{
			name: "empty repo, default template",
			args: args{
				repo: func() *git.Repository {
					workspace := t.TempDir()
					return mustCreateRepo(workspace, []gitObj{}, []gitObj{})
				},
				template: defaultTemplate,
				newTag:   annotatedTag{Name: "a", Message: "b"},
			},
			want:    "",
			wantErr: errNoAnnotatedTags,
		},
		{
			name: "2 commits, 1 tag, default template",
			args: args{
				newTag: annotatedTag{Name: "v0.7.6", Message: "this is the new tag msg"},
				repo: func() *git.Repository {
					os.RemoveAll(workspace)
					workspace = t.TempDir()
					return mustCreateRepo(workspace,
						[]gitObj{
							{msg: "foo", timestamp: dummyTimestamp},
							{msg: "bar", timestamp: dummyTimestamp},
						},
						[]gitObj{
							{
								msg:       "this is my tag msg",
								name:      "v0.7.5",
								timestamp: dummyTimestamp,
							},
						})
				},
				template: defaultTemplate,
			},
			want:    "## v0.7.6\n**this is the new tag msg**\n\n* bar\n* foo\n\n",
			wantErr: nil,
		},
		{
			name: "3 commits,2 tags, custom template",
			args: args{
				newTag: annotatedTag{Name: "v0.7.6", Message: "this is the new tag msg"},
				repo: func() *git.Repository {
					os.RemoveAll(workspace)
					workspace = t.TempDir()
					return mustCreateRepo(workspace,
						[]gitObj{
							{msg: "foo", timestamp: dummyTimestamp},
							{msg: "bar", timestamp: dummyTimestamp},
							{msg: "baz", timestamp: dummyTimestamp},
						}, []gitObj{
							{
								msg:          "this is my tag msg",
								name:         "v0.7.1",
								timestamp:    dummyTimestamp,
								tagCommitNum: 0,
							},
							{
								msg:          "this is my other tag msg",
								name:         "v0.7.5",
								timestamp:    "2024-01-19T18:09:06Z",
								tagCommitNum: 1,
							},
						})

				},
				template: "{{.Tag}}",
			},

			want:    "v0.7.6",
			wantErr: nil,
		},
		{
			name: "3 commits,2 tags, HEAD is on the latest tag so we are generating a changelog for the previous",
			args: args{
				newTag: annotatedTag{},
				repo: func() *git.Repository {
					os.RemoveAll(workspace)
					workspace = t.TempDir()
					return mustCreateRepo(workspace,
						[]gitObj{
							{msg: "foo", timestamp: dummyTimestamp},
							{msg: "bar", timestamp: dummyTimestamp},
							{msg: "baz", timestamp: dummyTimestamp},
						}, []gitObj{
							{
								msg:          "this is my other tag msg",
								name:         "v0.7.5",
								timestamp:    "2024-01-19T18:09:06Z",
								tagCommitNum: 1,
							},
							{
								msg:          "this is my HEAD tag msg",
								name:         "v0.7.7",
								timestamp:    "2024-02-19T18:09:06Z",
								tagCommitNum: 2,
							},
						})

				},
				template: "{{.Tag}}",
			},

			want:    "v0.7.7",
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := generateChangelog(tt.args.repo(), tt.args.newTag, tt.args.template)
			if (err != nil) && err != tt.wantErr {
				t.Errorf("generateChangelog() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("generateChangelog() = '%v', want '%v'", got, tt.want)
			}
		})
	}
	os.RemoveAll(workspace)
}
