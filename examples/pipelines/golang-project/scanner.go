package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/smithy-security/smithy/sdk/component"
	ocsf "github.com/smithy-security/smithy/sdk/gen/com/github/ocsf/ocsf_schema/v1"
)

const goSecOutPath = "gosec_out.json"

var (
	confidences = map[string]*ocsf.VulnerabilityFinding_ConfidenceId{
		"LOW":    ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_LOW),
		"MEDIUM": ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_MEDIUM),
		"HIGH":   ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH),
		"OTHER":  ptr(ocsf.VulnerabilityFinding_CONFIDENCE_ID_OTHER),
	}
	severities = map[string]ocsf.VulnerabilityFinding_SeverityId{
		"CRITICAL":      ocsf.VulnerabilityFinding_SEVERITY_ID_CRITICAL,
		"MEDIUM":        ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM,
		"LOW":           ocsf.VulnerabilityFinding_SEVERITY_ID_LOW,
		"OTHER":         ocsf.VulnerabilityFinding_SEVERITY_ID_OTHER,
		"FATAL":         ocsf.VulnerabilityFinding_SEVERITY_ID_FATAL,
		"INFORMATIONAL": ocsf.VulnerabilityFinding_SEVERITY_ID_INFORMATIONAL,
		"HIGH":          ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH,
	}
)

type (
	goSecScanner struct {
		repoPath       string
		dockerTestPool *dockertest.Pool
	}

	GoSecOut struct {
		Issues []GoSecIssue `json:"Issues"`
	}

	GoSecIssue struct {
		Severity     string   `json:"severity"`
		Confidence   string   `json:"confidence"`
		Cwe          GoSecCwe `json:"cwe"`
		RuleID       string   `json:"rule_id"`
		Details      string   `json:"details"`
		File         string   `json:"file"`
		Code         string   `json:"code"`
		Line         string   `json:"line"`
		Column       string   `json:"column"`
		Nosec        bool     `json:"nosec"`
		Suppressions any      `json:"suppressions"`
	}

	GoSecCwe struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
)

func NewGoSecScanner(repoPath string) (*goSecScanner, error) {
	if repoPath == "" {
		return nil, errors.New("must specify a repository path")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		return nil, fmt.Errorf("could not connect to docker: %w", err)
	}

	return &goSecScanner{
		repoPath:       repoPath,
		dockerTestPool: pool,
	}, nil
}

func (g *goSecScanner) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	if err := g.runGoSec(ctx); err != nil {
		return nil, fmt.Errorf("could not run gosec: %w", err)
	}

	vulns, err := g.parseVulns(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not parse vulns: %w", err)
	}

	return vulns, nil
}

func (g *goSecScanner) parseVulns(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	f, err := os.Open(goSecOutPath)
	if err != nil {
		return nil, fmt.Errorf("could not open gosec_out.json: %w", err)
	}

	defer func() {
		if err := f.Close(); err != nil {
			component.
				LoggerFromContext(ctx).
				Error(
					"could not close gosec_out.json",
					slog.String("err", err.Error()),
				)
		}

		if err := os.RemoveAll(goSecOutPath); err != nil {
			component.
				LoggerFromContext(ctx).
				Error(
					"could not remove gosec_out.json",
					slog.String("err", err.Error()),
				)
		}
	}()

	b, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("could not read gosec_out.json: %w", err)
	}

	var out GoSecOut
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("could not decode gosec_out.json: %w", err)
	}

	var (
		vulns = make([]*ocsf.VulnerabilityFinding, 0, len(out.Issues))
		now   = time.Now().Unix()
	)

	for _, issue := range out.Issues {
		vulns = append(vulns, &ocsf.VulnerabilityFinding{
			ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
			CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
			ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
			Confidence:   &issue.Confidence,
			ConfidenceId: confidences[issue.Confidence],
			Count:        ptr(int32(1)),
			FindingInfo: &ocsf.FindingInfo{
				CreatedTime: &now,
				DataSources: []string{
					issue.File,
				},
				Desc:          &issue.Details,
				FirstSeenTime: &now,
				LastSeenTime:  &now,
				ModifiedTime:  &now,
				ProductUid:    ptr("gosec"),
				Title:         issue.Details,
				Uid:           issue.RuleID,
			},
			Message: ptr(issue.Details),
			Resource: &ocsf.ResourceDetails{
				Uid: ptr(
					strings.Join([]string{
						issue.File,
						issue.Line,
						issue.Column,
					},
						":",
					),
				),
				Data: &structpb.Value{
					Kind: &structpb.Value_StringValue{
						StringValue: issue.Code,
					},
				},
			},
			RawData:    ptr(string(b)),
			Severity:   &issue.Severity,
			SeverityId: severities[issue.Severity],
			StartTime:  &now,
			Status:     ptr("opened"),
			Time:       now,
			TypeUid: int64(
				ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.Number()*
					100 +
					ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.Number(),
			),
			Vulnerabilities: []*ocsf.Vulnerability{
				{
					Cwe: &ocsf.Cwe{
						Uid:    issue.Cwe.ID,
						SrcUrl: &issue.Cwe.URL,
					},
				},
			},
		})
	}

	return vulns, nil
}

func (g *goSecScanner) runGoSec(ctx context.Context) error {
	p, err := filepath.Abs(".")
	if err != nil {
		return fmt.Errorf("could not get absolute path: %w", err)
	}

	component.
		LoggerFromContext(ctx).
		Info("preparing to run gosec",
			slog.String("path", path.Join(p, g.repoPath)),
			slog.String("output", goSecOutPath),
		)

	r, err := g.dockerTestPool.RunWithOptions(&dockertest.RunOptions{
		Platform:   "linux/amd64",
		Repository: "docker.io/securego/gosec",
		Tag:        "2.15.0",
		WorkingDir: "/workspace",
		Cmd: []string{
			"-r",
			"-sort",
			"-nosec",
			"-fmt=json",
			fmt.Sprintf("-out=%s", goSecOutPath),
			"-no-fail",
			fmt.Sprintf("./%s", g.repoPath),
		},
	}, func(config *docker.HostConfig) {
		config.AutoRemove = true
		config.Binds = []string{fmt.Sprintf("%s:/workspace", p)}
	})
	if err != nil {
		return fmt.Errorf("could not start gosec container: %w", err)
	}

	if err := g.dockerTestPool.Client.Logs(docker.LogsOptions{
		Context:      ctx,
		Container:    r.Container.ID,
		OutputStream: os.Stdout,
		ErrorStream:  os.Stderr,
		Stdout:       true,
		Stderr:       true,
		Follow:       true,
	}); err != nil {
		log.Fatalf("Could not retrieve logs: %s", err)
	}

	return nil
}
