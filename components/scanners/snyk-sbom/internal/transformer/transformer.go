package transformer

import (
	"context"
	"crypto/tls"
	"log"
	"log/slog"
	"net/http"
	"os"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/go-errors/errors"
	"github.com/google/uuid"
	"github.com/smithy-security/pkg/env"

	"github.com/smithy-security/smithy/sdk/component"

	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

type (
	// SnykTransformerOption allows customising the transformer.
	SnykTransformerOption func(g *snykTransformer) error

	snykTransformer struct {
		rawOutFilePath string
		apiKey         string
		apiURL         string
		projectName    string
		projectUUID    string
		projectVersion string
		debug          bool
		dtClient       dtrack.Client
	}
)

// SnykTransformerWithDTClient allows customising the underlying dependency track client.
func SnykTransformerWithDTClient(client *dtrack.Client) SnykTransformerOption {
	return func(g *snykTransformer) error {
		if client == nil {
			return errors.Errorf("invalid nil client")
		}
		g.dtClient = *client
		return nil
	}
}

// New returns a new snyk transformer.
func New(opts ...SnykTransformerOption) (*snykTransformer, error) {
	rawOutFilePath, err := env.GetOrDefault(
		"RAW_OUT_FILE_PATH",
		"",
		env.WithDefaultOnError(false),
	)
	if err != nil {
		return nil, err
	}

	dtAPIKey, err := env.GetOrDefault(
		"DEPENDENCY_TRACK_API_KEY",
		"",
		env.WithDefaultOnError(false),
	)
	if err != nil {
		return nil, err
	}

	dtAPIURL, err := env.GetOrDefault(
		"DEPENDENCY_TRACK_API_URL",
		"",
		env.WithDefaultOnError(false),
	)
	if err != nil {
		return nil, err
	}

	dtProjectName, err := env.GetOrDefault(
		"DEPENDENCY_TRACK_PROJECT_NAME",
		"",
		env.WithDefaultOnError(false),
	)
	if err != nil {
		return nil, err
	}

	dtProjectUUID, err := env.GetOrDefault(
		"DEPENDENCY_TRACK_PROJECT_UUID",
		"",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	dtProjectVersion, err := env.GetOrDefault(
		"DEPENDENCY_TRACK_PROJECT_VERSION",
		"",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	debug, err := env.GetOrDefault(
		"DEBUG",
		"",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	t := snykTransformer{
		rawOutFilePath: rawOutFilePath,
		apiKey:         dtAPIKey,
		apiURL:         dtAPIURL,
		projectName:    dtProjectName,
		projectUUID:    dtProjectUUID,
		projectVersion: dtProjectVersion,
		debug:          len(debug) > 0,
	}

	for _, opt := range opts {
		if err := opt(&t); err != nil {
			return nil, errors.Errorf("failed to apply option: %w", err)
		}
	}

	if t.rawOutFilePath == "" {
		return nil, errors.New("invalid empty raw output file")
	}
	return &t, nil
}

// Transform uploads a Cyclonedx sbom to a waiting dependency track
func (g *snykTransformer) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	logger := component.
		LoggerFromContext(ctx)

	logger.Debug("preparing to upload raw snyk output...")

	b, err := os.ReadFile(g.rawOutFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.Errorf("raw output file '%s' not found", g.rawOutFilePath)
		}
		return nil, errors.Errorf("failed to read raw output file '%s': %w", g.rawOutFilePath, err)
	}
	if err := g.sendToDtrack(ctx, b); err != nil {
		return nil, errors.Errorf("failed to upload raw output file '%s': %w", g.rawOutFilePath, err)
	}
	return []*ocsf.VulnerabilityFinding{}, nil
}

func (g *snykTransformer) sendToDtrack(ctx context.Context, sbom []byte) error {
	client, err := dtrack.NewClient(
		g.apiURL,
		dtrack.WithHttpClient(
			&http.Client{Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: g.debug,
				},
			},
			}),
		dtrack.WithDebug(g.debug),
		dtrack.WithAPIKey(g.apiKey),
	)
	if err != nil {
		log.Fatalf("could not instantiate client err: %#v\n", err)
	}

	_, err = client.About.Get(ctx)
	if err != nil {
		return errors.Errorf("cannot connect to Dependency Track at %s, err:'%w'", g.apiURL, err)
	}

	slog.Info("Connection to Dependency Track successful")

	var tokens []string

	token, err := g.uploadBOM(string(sbom), g.projectVersion)
	if err != nil {
		return errors.Errorf("could not upload bom to dependency track, err:%w", err)
	}

	slog.Debug("upload", "token", token)
	tokens = append(tokens, token)
	return nil
}

func (g *snykTransformer) uploadBOM(bom string, projectVersion string) (string, error) {
	slog.Info("uploading BOM to Dependency Track", "projectName", g.projectName,
		"projectVersion", projectVersion)
	if projectVersion == "" {
		projectVersion = "Unknown"
	}
	projUUID, err := uuid.Parse(g.projectUUID)
	if err != nil {
		return "", err
	}
	token, err := g.dtClient.BOM.PostBom(context.TODO(), dtrack.BOMUploadRequest{
		ProjectName:    g.projectName,
		ProjectVersion: projectVersion,
		ProjectUUID:    &projUUID,
		AutoCreate:     true,
		BOM:            bom,
	})
	return string(token), err
}
