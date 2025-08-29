package transformer

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-errors/errors"
	"github.com/jonboulle/clockwork"
	"github.com/package-url/packageurl-go"
	"github.com/smithy-security/pkg/env"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

type (

	// NancyTransformerOption allows customising the transformer.
	NancyTransformerOption func(b *NancyTransformer) error

	// NancyOut represents the output of a nancy run that we care about.
	NancyOut struct {
		Vulnerable    []NancyAdvisory `json:"vulnerable"`
		Audited       any             // unused
		Exclusions    any             // unused
		Invalid       any             // unused
		NumAudited    int
		NumVulnerable int
		Version       string
	}

	// NancyAdvisories represents a nancy advisory section that we care about.
	NancyAdvisory struct {
		Coordinates     string                `json:"Coordinates"`
		Reference       string                `json:"Reference"`
		Vulnerabilities []*NancyVulnerability `json:"Vulnerabilities"`
	}

	// NancyVulnerability represents a nancy vulnerability.
	NancyVulnerability struct {
		ID          string `json:"Id"`
		Title       string `json:"Title"`
		Description string `json:"Description"`
		CvssScore   string `json:"CvssScore"`
		CvssVector  string `json:"CvssVector"`
		Cve         string `json:"Cve"`
		Cwe         string `json:"Cwe"`
		Reference   string `json:"Reference"`
	}

	// NancyTransformer represents the nancy output parser
	NancyTransformer struct {
		targetType     ocsffindinginfo.DataSource_TargetType
		clock          clockwork.Clock
		rawOutFilePath string
		fileContents   []byte
		projectRoot    string
		goModPaths     []string
	}
)

var (
	// Generic errors

	// ErrNilClock is thrown when the option setclock is called with empty clock
	ErrNilClock = errors.Errorf("invalid nil clock")
	// ErrEmptyTarget is thrown when the option set target is called with empty target
	ErrEmptyTarget = errors.Errorf("invalid empty target")
	// ErrEmptyRawOutfilePath is thrown when the option raw outfile path is called with empty path
	ErrEmptyRawOutfilePath = errors.Errorf("invalid raw out file path")
	// ErrEmptyRawOutfileContents is thrown when the option raw outfile contents is called with empty contents
	ErrEmptyRawOutfileContents = errors.Errorf("empty raw out file contents")
	// ErrBadTargetType is thrown when the option set target type is called with an unspecified or empty target type
	ErrBadTargetType = errors.New("invalid empty target type")

	// Nancy Parser Specific Errors

	// ErrNoLineRange is thrown when nancy produces a finding without a line range
	ErrNoLineRange = errors.Errorf("nancy result does not contain a line range")
	// ErrBadDataSource is thrown when nancy produces a finding that cannot have a datasource (e.g. no filename)
	ErrBadDataSource = errors.Errorf("failed to marshal data source to JSON")
	// ErrEmptyPath is thrown when called with an empty project root
	ErrEmptyPath = errors.Errorf("called with an empty project root")
	// ErrCouldNotFindPackage is thrown when nancy cannot find the dependency in any go.mod files
	ErrCouldNotFindPackage = errors.Errorf("could not find package")
)

// NancyTransformerWithClock allows customising the underlying clock.
func NancyTransformerWithClock(clock clockwork.Clock) NancyTransformerOption {
	return func(g *NancyTransformer) error {
		if clock == nil {
			return ErrNilClock
		}
		g.clock = clock
		return nil
	}
}

// NancyTransformerWithProjectRoot allows customising the path of the target project root
func NancyTransformerWithProjectRoot(path string) NancyTransformerOption {
	return func(g *NancyTransformer) error {
		if path == "" {
			return ErrEmptyPath
		}
		g.projectRoot = path
		return nil
	}
}

// NancyTransformerWithTarget allows customising the underlying target type.
func NancyTransformerWithTarget(target ocsffindinginfo.DataSource_TargetType) NancyTransformerOption {
	return func(g *NancyTransformer) error {
		if target == ocsffindinginfo.DataSource_TARGET_TYPE_UNSPECIFIED {
			return ErrEmptyTarget
		}
		g.targetType = target
		return nil
	}
}

// NancyRawOutFilePath allows customising the underlying raw out file path.
func NancyRawOutFilePath(path string) NancyTransformerOption {
	return func(g *NancyTransformer) error {
		if path == "" {
			return ErrEmptyRawOutfilePath
		}
		g.rawOutFilePath = path
		return nil
	}
}

// NancyRawOutFileContents allows customising the underlying raw out file contents.
func NancyRawOutFileContents(contents []byte) NancyTransformerOption {
	return func(g *NancyTransformer) error {
		if contents == nil {
			return ErrEmptyRawOutfileContents
		}
		g.fileContents = contents
		return nil
	}
}

// New returns a new nancy transformer.
func New(opts ...NancyTransformerOption) (*NancyTransformer, error) {
	rawOutFilePath, err := env.GetOrDefault(
		"NANCY_RAW_OUT_FILE_PATH",
		"nancy.json",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	tt, err := env.GetOrDefault(
		"NANCY_TARGET_TYPE",
		ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY.String(),
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	projectRoot, err := env.GetOrDefault(
		"NANCY_SCANNED_PROJECT_ROOT",
		"",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	t := NancyTransformer{
		rawOutFilePath: rawOutFilePath,
		targetType:     ocsffindinginfo.DataSource_TargetType(ocsffindinginfo.DataSource_TargetType_value[tt]),
		clock:          clockwork.NewRealClock(),
		projectRoot:    projectRoot,
	}

	for _, opt := range opts {
		if err := opt(&t); err != nil {
			return nil, errors.Errorf("failed to apply option: %w", err)
		}
	}

	goModFiles, err := findFiles(t.projectRoot, "go.mod", "/vendor/")
	if err != nil {
		return nil, err
	}
	t.goModPaths = goModFiles

	switch {
	case t.targetType == ocsffindinginfo.DataSource_TARGET_TYPE_UNSPECIFIED:
		return nil, ErrBadTargetType
	case t.projectRoot == "":
		return nil, errors.New("invalid project root, cannot be empty")
	}
	return &t, nil
}

// Transform transforms raw sarif findings into ocsf vulnerability findings.
func (b *NancyTransformer) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	logger := componentlogger.LoggerFromContext(ctx)

	logger.Debug("preparing to parse raw nancy output...")
	if b.fileContents == nil {
		inFile, err := os.ReadFile(b.rawOutFilePath)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, errors.Errorf("raw output file '%s' not found", b.rawOutFilePath)
			}
			return nil, errors.Errorf("failed to read raw output file '%s': %w", b.rawOutFilePath, err)
		}

		if len(inFile) == 0 {
			logger.Info("raw nancy output file is empty, no findings to parse, exiting")
			return []*ocsf.VulnerabilityFinding{}, nil
		}

		b.fileContents = inFile
	}

	var results NancyOut
	if err := json.Unmarshal(b.fileContents, &results); err != nil {
		return nil, errors.Errorf("could not unmarshal nancy output, err: %w", err)
	}
	vulns := make([]*ocsf.VulnerabilityFinding, 0)

	logger.Info("received", slog.Int("num_raw_nancy_findings", len(results.Vulnerable)))
	for _, res := range results.Vulnerable {
		v, err := b.parseResult(ctx, res)
		if err != nil {
			return nil, errors.Errorf("could not parse nancy result, err: %w", err)
		}
		vulns = append(vulns, v...)
	}

	logger.Debug(
		"successfully parsed raw nancy findings to ocsf vulnerability findings!",
		slog.Int("num_parsed_nancy_findings", len(vulns)),
	)
	return vulns, nil
}

func (b *NancyTransformer) cvssToSeverity(score float64) ocsf.VulnerabilityFinding_SeverityId {
	switch {
	case 0.1 <= score && score <= 3.9:
		return ocsf.VulnerabilityFinding_SEVERITY_ID_LOW
	case 4.0 <= score && score <= 6.9:
		return ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM
	case 7.0 <= score && score <= 8.9:
		return ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH
	case 9.0 <= score && score <= 10.0:
		return ocsf.VulnerabilityFinding_SEVERITY_ID_CRITICAL
	default:
		return ocsf.VulnerabilityFinding_SEVERITY_ID_INFORMATIONAL
	}
}

func (b *NancyTransformer) parseResult(ctx context.Context, advisory NancyAdvisory) ([]*ocsf.VulnerabilityFinding, error) {
	now := b.clock.Now().Unix()
	confidenceID := ocsf.VulnerabilityFinding_CONFIDENCE_ID_HIGH
	confidence := ocsf.VulnerabilityFinding_ConfidenceId_name[int32(confidenceID)]
	results := []*ocsf.VulnerabilityFinding{}
	affectedCode, err := b.mapCode(advisory)
	if err != nil {
		slog.Info("could not find the direct dependency this likely means that there is a vulnerability in a transitive dependency which you may not care about", slog.String("purl", advisory.Coordinates))
	}
	for _, vulnerability := range advisory.Vulnerabilities {
		dataSource, err := b.mapDataSource(ctx, advisory)
		if err != nil {
			return nil, err
		}
		cvss, err := strconv.ParseFloat(vulnerability.CvssScore, 64)
		if err != nil {
			return nil, err
		}
		purl, err := packageurl.FromString(advisory.Coordinates)
		if err != nil {
			return nil, errors.Errorf("could not parse advisory coordinates to purl, coordinates: %s, err: %w", advisory.Coordinates, err)
		}
		finding := &ocsf.VulnerabilityFinding{

			ActivityName: Ptr(ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.String()),
			ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
			CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
			ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
			ClassName:    Ptr(ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.String()),
			Confidence:   &confidence,

			ConfidenceId: Ptr(ocsf.VulnerabilityFinding_ConfidenceId(confidenceID)),
			Count:        Ptr(int32(1)),
			FindingInfo: &ocsf.FindingInfo{
				Uid:         "Vulnerable-Go-Dependency", // TODO: make this a constant and share across SCA
				CreatedTime: &now,
				DataSources: []string{
					dataSource,
				},
				Desc:          &vulnerability.Description,
				FirstSeenTime: &now,
				LastSeenTime:  &now,
				ModifiedTime:  &now,
				ProductUid:    Ptr("nancy"),
				Title:         vulnerability.Title,
			},
			Message:    &vulnerability.Description,
			Severity:   Ptr(ocsf.VulnerabilityFinding_SeverityId_name[int32(b.cvssToSeverity(cvss))]),
			SeverityId: ocsf.VulnerabilityFinding_SeverityId(b.cvssToSeverity(cvss)),
			StartTime:  &now,
			Status:     Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW.String()),
			StatusId:   Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
			Time:       now,
			TypeUid: int64(
				ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.Number()*
					100 +
					ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.Number(),
			),
			Vulnerabilities: []*ocsf.Vulnerability{
				{
					AffectedCode: affectedCode,
					AffectedPackages: []*ocsf.AffectedPackage{
						{
							PackageManager: &purl.Namespace,
							Name:           purl.Name,
							Purl:           Ptr(purl.String()),
							Version:        purl.Version,
							Path:           &purl.Subpath,
						},
					},
					Cwe:           b.optionallyMapCWE(vulnerability),
					Desc:          Ptr(vulnerability.Description),
					FirstSeenTime: &now,
					Cve: &ocsf.Cve{
						Cvss: []*ocsf.Cvss{
							{
								VectorString: &vulnerability.CvssVector,
								OverallScore: &cvss,
							},
						},
					},
					LastSeenTime: &now,
					Severity:     Ptr(ocsf.VulnerabilityFinding_SeverityId_name[int32(b.cvssToSeverity(cvss))]),
					Title:        Ptr(vulnerability.Title),
					VendorName:   Ptr("nancy"),
				},
			},
		}
		results = append(results, finding)
	}
	return results, nil
}

func (n *NancyTransformer) mapCode(r NancyAdvisory) ([]*ocsf.AffectedCode, error) {
	pp, err := packageurl.FromString(r.Coordinates)
	if err != nil {
		return nil, fmt.Errorf("failed to parse purl: %w", err)
	}

	substring := fmt.Sprintf("%s/%s", pp.Namespace, pp.Name)
	version := pp.Version
	result := []*ocsf.AffectedCode{}
	found := false
	for _, gomod := range n.goModPaths {
		file, err := os.Open(gomod)
		if err != nil {
			return nil, errors.Errorf("Error opening file: %w", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		lineNumber := 0

		for scanner.Scan() {
			lineNumber++
			line := scanner.Text()
			if strings.Contains(line, substring) && strings.Contains(line, version) {
				found = true
				result = append(result, &ocsf.AffectedCode{
					File: &ocsf.File{
						Path: &gomod,
						Name: "go.mod",
					},
					StartLine: Ptr(int32(lineNumber)),
					EndLine:   Ptr(int32(lineNumber)),
				})
			}
			if err := scanner.Err(); err != nil {
				return nil, err
			}
		}
	}
	if !found {
		return nil, errors.Errorf("%w: '%s' in any go.mod in this project, list of go.mod files: '%v', tried to match substring '%s' and version: '%s'", ErrCouldNotFindPackage, r.Coordinates, n.goModPaths, substring, version)
	}
	return result, nil
}

func findFiles(root, targetName, excludeFromPath string) ([]string, error) {
	var matches []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Check if it's a file (not a directory) and matches the target name
		if !info.IsDir() && info.Name() == targetName && !strings.Contains(path, excludeFromPath) {
			matches = append(matches, path)
		}
		return nil
	})

	if err != nil {
		return nil, errors.Errorf("error walking directory tree with root at: %s, err: %w", root, err)
	}
	return matches, nil
}

func (*NancyTransformer) optionallyMapCWE(r *NancyVulnerability) *ocsf.Cwe {
	re := regexp.MustCompile(`CWE-(\d+)`)
	match := re.FindStringSubmatch(r.Title)
	if len(match) > 1 {
		return &ocsf.Cwe{
			Uid: match[1],
		}
	} else {
		return nil
	}
}

func (b *NancyTransformer) mapDataSource(ctx context.Context, r NancyAdvisory) (string, error) {
	targetMetadata := component.TargetMetadataFromCtx(ctx)

	dataSource := ocsffindinginfo.DataSource{
		TargetType: b.targetType,
		Uri: &ocsffindinginfo.DataSource_URI{
			UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_PURL,
			Path:      r.Coordinates,
		},
		SourceCodeMetadata: targetMetadata.SourceCodeMetadata,
		LocationData: &ocsffindinginfo.DataSource_PurlFindingLocationData_{
			PurlFindingLocationData: &ocsffindinginfo.DataSource_PurlFindingLocationData{},
		},
	}

	toBytes, err := protojson.Marshal(&dataSource)
	if err != nil {
		return "", errors.Errorf("%w err:%w", ErrBadDataSource, err)
	}
	return string(toBytes), nil
}

// Ptr returns the pointer to the passed value.
func Ptr[T any](v T) *T {
	return &v
}
