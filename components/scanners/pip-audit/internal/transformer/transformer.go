package transformer

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-errors/errors"
	"github.com/jonboulle/clockwork"
	"github.com/package-url/packageurl-go"
	"github.com/smithy-security/pkg/env"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/new-components/scanners/pip-audit/internal/util/ptr"
	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

const (
	depsFileTypes depsFileType = iota
	requirements
	pyproject
)

type (

	// PipAuditTransformerOption allows customising the transformer.
	PipAuditTransformerOption func(b *PipAuditTransformer) error

	depsFileType int
	depsFile     struct {
		path     string
		fileType depsFileType
	}

	PipAuditOut struct {
		Dependencies []Dependency `json:"dependencies"`
		Fixes        []Fix        `json:"fixes"`
	}

	Dependency struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Vulns   []Vuln `json:"vulns"`
	}

	Vuln struct {
		ID          string   `json:"id"`
		FixVersions []string `json:"fix_versions"`
		Aliases     []string `json:"aliases"`
		Description string   `json:"description"`
	}

	Fix struct {
		Name       string `json:"name"`
		OldVersion string `json:"old_version"`
		NewVersion string `json:"new_version"`
	}

	// PipAuditTransformer represents the pip-audit output parser
	PipAuditTransformer struct {
		targetType      ocsffindinginfo.DataSource_TargetType
		clock           clockwork.Clock
		rawOutFilePath  string
		fileContents    []byte
		projectRoot     string
		dependencyFiles []depsFile
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

	// PipAudit Parser Specific Errors
	// ErrEmptyPath is thrown when called with an empty project root
	ErrEmptyPath = errors.Errorf("called with an empty project root")
	// ErrNoLineRange is thrown when pip-audit produces a finding without a line range
	ErrNoLineRange = errors.Errorf("pip-audit result does not contain a line range")
	// ErrBadDataSource is thrown when pip-audit produces a finding that cannot have a datasource (e.g. no filename)
	ErrBadDataSource = errors.Errorf("failed to marshal data source to JSON")
	// ErrCouldNotFindPackage is thrown when nancy cannot find the dependency in any go.mod files
	ErrCouldNotFindPackage = errors.Errorf("could not find package")
)

// PipAudityTransformerWithClock allows customising the underlying clock.
func PipAuditTransformerWithClock(clock clockwork.Clock) PipAuditTransformerOption {
	return func(g *PipAuditTransformer) error {
		if clock == nil {
			return ErrNilClock
		}
		g.clock = clock
		return nil
	}
}

// PipAuditRawOutFilePath allows customising the underlying raw out file path.
func PipAuditRawOutFilePath(path string) PipAuditTransformerOption {
	return func(g *PipAuditTransformer) error {
		if path == "" {
			return ErrEmptyRawOutfilePath
		}
		g.rawOutFilePath = path
		return nil
	}
}

// PipAuditRawOutFileContents allows customising the underlying raw out file contents.
func PipAuditRawOutFileContents(contents []byte) PipAuditTransformerOption {
	return func(g *PipAuditTransformer) error {
		if contents == nil {
			return ErrEmptyRawOutfileContents
		}
		g.fileContents = contents
		return nil
	}
}

// PipAuditTransformerWithProjectRoot allows customising the path of the target project root
func PipAuditTransformerWithProjectRoot(path string) PipAuditTransformerOption {
	return func(g *PipAuditTransformer) error {
		if path == "" {
			return ErrEmptyPath
		}
		g.projectRoot = path
		return nil
	}
}

// New returns a new pip-audit transformer.
func New(opts ...PipAuditTransformerOption) (*PipAuditTransformer, error) {
	rawOutFilePath, err := env.GetOrDefault(
		"PIP_AUDIT_RAW_OUT_FILE_PATH",
		"pip-audit.json",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	projectRoot, err := env.GetOrDefault(
		"PIP_AUDIT_SCANNED_PROJECT_ROOT",
		"",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	reqsFileName, err := env.GetOrDefault(
		"REQUIREMENTS_FILE_NAME",
		"requirements.txt",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	pyprojFileName, err := env.GetOrDefault(
		"PYPROJECT_FILE_NAME",
		"pyproject.toml",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	t := PipAuditTransformer{
		rawOutFilePath: rawOutFilePath,
		clock:          clockwork.NewRealClock(),
		projectRoot:    projectRoot,
		targetType:     ocsffindinginfo.DataSource_TARGET_TYPE_REPOSITORY,
	}

	for _, opt := range opts {
		if err := opt(&t); err != nil {
			return nil, errors.Errorf("failed to apply option: %w", err)
		}
	}

	requirementsTxt, err := findFiles(t.projectRoot, reqsFileName, []string{"v", "venv", "virtualenv"})
	if err != nil {
		return nil, err
	}

	pyprojectTomls, err := findFiles(t.projectRoot, pyprojFileName, []string{"v", "venv", "virtualenv"})
	if err != nil {
		return nil, err
	}

	for _, r := range requirementsTxt {
		t.dependencyFiles = append(t.dependencyFiles, depsFile{
			path:     r,
			fileType: requirements,
		})
	}

	for _, r := range pyprojectTomls {
		t.dependencyFiles = append(t.dependencyFiles, depsFile{
			path:     r,
			fileType: pyproject,
		})
	}
	return &t, nil
}

// Transform transforms raw sarif findings into ocsf vulnerability findings.
func (b *PipAuditTransformer) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	logger := component.LoggerFromContext(ctx)

	logger.Debug("preparing to parse raw pip-audit output...")
	if b.fileContents == nil {
		inFile, err := os.ReadFile(b.rawOutFilePath)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, errors.Errorf("raw output file '%s' not found", b.rawOutFilePath)
			}
			return nil, errors.Errorf("failed to read raw output file '%s': %w", b.rawOutFilePath, err)
		}
		b.fileContents = inFile
	}
	var results PipAuditOut
	if err := json.Unmarshal(b.fileContents, &results); err != nil {
		return nil, errors.Errorf("could not unmarshal pip-audit output, err: %w", err)
	}
	vulns := make([]*ocsf.VulnerabilityFinding, 0)

	for _, res := range results.Dependencies {
		v, err := b.parseResult(&res, results.Fixes)
		if err != nil {
			return nil, errors.Errorf("could not parse pip-audit result, err: %w", err)
		}
		if v != nil {
			vulns = append(vulns, v)
		}
	}

	logger.Debug(
		"successfully parsed raw pip-audit findings to ocsf vulnerability findings!",
		slog.Int("num_parsed_pip_audit_findings", len(vulns)),
	)
	return vulns, nil
}

func (b *PipAuditTransformer) parseResult(r *Dependency, fixes []Fix) (*ocsf.VulnerabilityFinding, error) {
	if len(r.Vulns) == 0 {
		return nil, nil
	}
	now := b.clock.Now().Unix()
	name := strings.ToLower(strings.ReplaceAll(r.Name, "_", "-")) //as per https://github.com/package-url/purl-spec/blob/main/PURL-TYPES.rst#pypi
	pp := packageurl.NewPackageURL(packageurl.TypePyPi, "", name, r.Version, packageurl.Qualifiers{}, "")
	affectedCode, err := b.mapCode(r, pp)
	if err != nil {
		return nil, errors.Errorf("failed to map code: %w", err)
	}
	dataSources, err := b.mapDataSources(r, affectedCode)
	if err != nil {
		return nil, errors.Errorf("failed to map data source: %w", err)
	}
	references := []string{}
	desc := fmt.Sprintf("the library: %s:%s has the following vulnerabilities:", r.Name, r.Version)
	for _, v := range r.Vulns {
		desc = fmt.Sprintf("%s\n* %s", desc, v.Description)
		references = append(references, v.Aliases...)
		references = append(references, v.ID)
	}
	title := fmt.Sprintf("%s:%s is vulnerable", r.Name, r.Version)

	remediationDesc := ""
	for _, fix := range fixes {
		if fix.Name == r.Name {
			remediationDesc = fmt.Sprintf("Upgrade %s from version %s to version %s", fix.Name, fix.OldVersion, fix.NewVersion)
		}
	}
	return &ocsf.VulnerabilityFinding{ // TODO: we really need an easy way to just include/generate the patch
		ActivityName: ptr.Ptr(ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.String()),
		ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
		CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
		ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
		ClassName:    ptr.Ptr(ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.String()),

		Count: ptr.Ptr(int32(1)),
		FindingInfo: &ocsf.FindingInfo{
			Uid:           pp.String(),
			CreatedTime:   &now,
			DataSources:   dataSources,
			Desc:          ptr.Ptr(desc),
			FirstSeenTime: &now,
			LastSeenTime:  &now,
			ModifiedTime:  &now,
			ProductUid:    ptr.Ptr("pip-audit"),
			Title:         title,
		},
		Message:   &desc,
		StartTime: &now,
		Status:    ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW.String()),
		StatusId:  ptr.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
		Time:      now,
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
						Name:           r.Name,
						PackageManager: ptr.Ptr("pypi"),
						Purl:           ptr.Ptr(pp.String()),
					},
				},
				Remediation: &ocsf.Remediation{
					Desc: remediationDesc,
				},
				References:    references,
				Desc:          &desc,
				FirstSeenTime: &now,
				LastSeenTime:  &now,
				Title:         &title,
				VendorName:    ptr.Ptr("pip-audit"),
			},
		},
	}, nil
}

func (b *PipAuditTransformer) mapDataSources(r *Dependency, affectedCode []*ocsf.AffectedCode) ([]string, error) {
	var result []string
	for _, ac := range affectedCode {
		var startLine, endLine uint32
		if ac.StartLine != nil {
			startLine = uint32(*ac.StartLine)
		}
		if ac.EndLine != nil {
			endLine = uint32(*ac.EndLine)
		}
		datasource := &ocsffindinginfo.DataSource{
			TargetType: b.targetType,
			Uri: &ocsffindinginfo.DataSource_URI{
				UriSchema: ocsffindinginfo.DataSource_URI_SCHEMA_FILE,
				Path:      *ac.File.Path,
			},
			LocationData: &ocsffindinginfo.DataSource_FileFindingLocationData_{
				FileFindingLocationData: &ocsffindinginfo.DataSource_FileFindingLocationData{
					StartLine: startLine,
					EndLine:   endLine,
				},
			},
		}
		toBytes, err := protojson.Marshal(datasource)
		if err != nil {
			return nil, errors.Errorf("%w err:%w", ErrBadDataSource, err)
		}
		result = append(result, string(toBytes))
	}
	return result, nil
}

func findInDependencies(filePath string, dependency *packageurl.PackageURL) ([]*ocsf.AffectedCode, error) {
	var acs []*ocsf.AffectedCode
	file, err := os.Open(filePath)
	if err != nil {
		return nil, errors.Errorf("Error opening file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	substring := dependency.Name
	version := dependency.Version
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		lineCaseInsensitive := strings.ToLower(line)
		if strings.Contains(lineCaseInsensitive, substring) && strings.Contains(lineCaseInsensitive, version) {
			acs = append(acs, &ocsf.AffectedCode{
				File: &ocsf.File{
					Path: &filePath,
					Name: "go.mod",
				},
				StartLine: ptr.Ptr(int32(lineNumber)),
				EndLine:   ptr.Ptr(int32(lineNumber)),
			})
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	if len(acs) != 0 {
		return acs, nil
	}
	return nil, errors.Errorf("did not find finding %s in file %s", dependency.String(), filePath)

}

func (n *PipAuditTransformer) mapCode(r *Dependency, pp *packageurl.PackageURL) ([]*ocsf.AffectedCode, error) {
	result := []*ocsf.AffectedCode{}
	found := false
	for _, df := range n.dependencyFiles {
		var code []*ocsf.AffectedCode
		var err error
		code, err = findInDependencies(df.path, pp)
		if err != nil {
			return nil, err
		}
		found = true
		result = append(result, code...)
	}
	if !found {
		return nil, errors.Errorf("%w: '%s' in any dependencies file in this project, list of dependency files: '%v', tried to match version: '%s'",
			ErrCouldNotFindPackage, r.Name, n.dependencyFiles, r.Version)
	}
	return result, nil
}

func findFiles(root, targetName string, excludeFromPath []string) ([]string, error) {
	var matches []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// skip directories that should be excluded
		if info.IsDir() {
			directoryShouldBeExcluded := slices.ContainsFunc(
				excludeFromPath,
				func(excludedPath string) bool {
					return filepath.Base(path) == excludedPath
				},
			)
			if directoryShouldBeExcluded {
				return filepath.SkipDir
			}

			return nil
		}

		// skip links
		if !info.Mode().IsRegular() {
			return nil
		}

		// Check if the file name matches the target name
		if info.Name() == targetName {
			matches = append(matches, path)
		}

		return nil
	})

	if err != nil {
		return nil, errors.Errorf("error walking directory tree with root at: %s, err: %w", root, err)
	}

	return matches, nil
}
