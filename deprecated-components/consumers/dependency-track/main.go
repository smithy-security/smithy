package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"strings"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/go-errors/errors"
	"github.com/google/uuid"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/deprecated-components/consumers"
	"github.com/smithy-security/smithy/pkg/cyclonedx"
)

var (
	authURL         string
	apiKey          string
	projectName     string
	projectVersion  string
	projectUUID     string
	client          *dtrack.Client
	ownerAnnotation string
	// used for debugging, turns off certificate and enables debug
	debugDTConnection string
	debugDT           bool
)

func main() {
	flag.StringVar(&apiKey, "apiKey", "", "dependency track api key")
	flag.StringVar(&authURL, "url", "", "dependency track base url")
	flag.StringVar(&projectName, "projectName", "", "dependency track project name")
	flag.StringVar(&projectUUID, "projectUUID", "", "dependency track project name")
	flag.StringVar(&projectVersion, "projectVersion", "", "dependency track project version")
	flag.StringVar(&debugDTConnection, "debugDependencyTrackConnection", "false", "setup client with no tls and enable debug")
	flag.StringVar(
		&ownerAnnotation,
		"ownerAnnotation",
		"",
		"if this consumer is in running after any enricher that adds ownership annotations, then provide the annotation-key for this enricher so it can tag owners as tags",
	)

	flag.Parse()

	if err := consumers.ParseFlags(); err != nil {
		log.Fatal(err)
	}
	if projectUUID == "" {
		log.Fatal("project uuid is mandatory for dependency track")
	}
	if authURL == "" {
		log.Fatal("auth url is mandatory for dependency track")
	}
	if apiKey == "" {
		log.Fatal("api key is mandatory for dependency track")
	}
	if projectName == "" {
		log.Fatal("project name is mandatory for dependency track")
	}
	if projectVersion == "" {
		log.Fatal("project version is mandatory for dependency track")
	}
	if debugDTConnection == "true" {
		debugDT = true
		slog.Info("running in debug mode, skipping certificate verification and printing requests and responses")
	}
	c, err := dtrack.NewClient(
		authURL,
		dtrack.WithHttpClient(
			&http.Client{Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: debugDT,
				},
			},
			}),
		dtrack.WithDebug(debugDT),
		dtrack.WithAPIKey(apiKey),
	)
	if err != nil {
		log.Fatalf("could not instantiate client err: %#v\n", err)
	}
	client = c
	abt, err := client.Metrics.LatestPortfolioMetrics(context.Background())
	if err != nil {
		log.Fatalf("cannot connect to Dependency Track at %s, err:'%v'", authURL, err)
	}
	slog.Info("Connection to DT successful, projects in instance:", "instance", abt.Projects)
	if consumers.Raw {
		responses, err := consumers.LoadToolResponse()
		if err != nil {
			log.Fatal("could not load raw results, file malformed: ", err)
		}
		if _, err := uploadBOMsFromRaw(responses); err != nil {
			log.Fatalf("could not upload boms from raw: %s", err)
		}

	} else {
		responses, err := consumers.LoadEnrichedToolResponse()
		if err != nil {
			log.Fatal("could not load enriched results, file malformed: ", err)
		}
		if _, err := uploadBOMSFromEnriched(responses); err != nil {
			log.Fatalf("could not upload boms from enriched: %s", err)
		}
	}
}

func uploadBOMSFromEnriched(responses []*v1.EnrichedLaunchToolResponse) ([]string, error) {
	var tokens []string
	for _, res := range responses {
		var bomIssue *v1.EnrichedIssue
		for _, issue := range res.GetIssues() {
			if issue.GetRawIssue().GetCycloneDXSBOM() != "" && bomIssue == nil {
				bomIssue = issue
			} else if bomIssue != nil && bomIssue.GetRawIssue().GetCycloneDXSBOM() != "" {
				slog.Error("tool:", res.GetOriginalResults().GetToolName(), "response is malformed, we expected a single issue with an SBOM as part of the tool, got something else instead")
				continue
			}
		}
		cdxbom, err := cyclonedx.FromSmithy(bomIssue.GetRawIssue())
		if err != nil {
			return tokens, err
		}
		token, err := uploadBOM(bomIssue.GetRawIssue().GetCycloneDXSBOM(), cdxbom.Metadata.Component.Version)
		if err != nil {
			return tokens, errors.Errorf("could not upload bom to dependency track, err:%w", err)
		}
		slog.Debug("upload", "token", token)
		tokens = append(tokens, token)
		if ownerAnnotation != "" {
			owners := []string{}
			for key, value := range bomIssue.Annotations {
				if strings.Contains(key, ownerAnnotation) {
					owners = append(owners, value)
				}
			}
			if err := addOwnersTags(owners); err != nil {
				slog.Error("could not tag owners", "err", err)
			}
		}
	}
	return tokens, nil
}

func uploadBOMsFromRaw(responses []*v1.LaunchToolResponse) ([]string, error) {
	var tokens []string
	for _, res := range responses {
		var bomIssue *v1.Issue
		for _, issue := range res.GetIssues() {
			if *issue.CycloneDXSBOM != "" && bomIssue == nil {
				bomIssue = issue
			} else if bomIssue != nil && *bomIssue.CycloneDXSBOM != "" {
				slog.Error("tool:", res.GetToolName(), "response is malformed, we expected a single issue with an SBOM as part of the tool, got something else instead")
				continue
			}
		}
		cdxbom, err := cyclonedx.FromSmithy(bomIssue)
		if err != nil {
			return tokens, err
		}
		token, err := uploadBOM(*bomIssue.CycloneDXSBOM, cdxbom.Metadata.Component.Version)
		if err != nil {
			return tokens, errors.Errorf("could not upload bod to dependency track, err:%w", err)
		}
		slog.Info("upload", "token", token)
		tokens = append(tokens, token)
	}
	return tokens, nil
}

func addOwnersTags(owners []string) error {
	// addOwnersTags expects a map of <ownerAnnotation>-<number>:<username> tagging owners
	// it then adds to the projectUUID the owners in the following tag format: Owner:<username>
	uuid := uuid.MustParse(projectUUID)
	project, err := client.Project.Get(context.Background(), uuid)
	if err != nil {
		slog.Error("could not add project tags error getting project by uuid", "err", err)
		return err
	}
	for _, owner := range owners {
		found := false
		for _, t := range project.Tags {
			if t.Name == fmt.Sprintf("%s:%s", ownerAnnotation, owner) {
				found = true
				break
			}
		}
		if !found {
			project.Tags = append(project.Tags, dtrack.Tag{Name: fmt.Sprintf("%s:%s", ownerAnnotation, owner)})
		}
	}
	_, err = client.Project.Update(context.Background(), project)
	return err
}

func uploadBOM(bom string, projectVersion string) (string, error) {
	slog.Info("uploading BOM to Dependency Track", "projectName", projectName, "projectVersion", projectVersion)
	if projectVersion == "" {
		projectVersion = "Unknown"
	}
	projUUID, err := uuid.Parse(projectUUID)
	if err != nil {
		return "", err
	}
	token, err := client.BOM.PostBom(context.TODO(), dtrack.BOMUploadRequest{
		ProjectName:    projectName,
		ProjectVersion: projectVersion,
		ProjectUUID:    &projUUID,
		AutoCreate:     true,
		BOM:            bom,
	})
	return string(token), err
}
