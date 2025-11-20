package transformer

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/go-errors/errors"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
	"github.com/smithy-security/pkg/languages"
	"github.com/smithy-security/pkg/utils"
	"github.com/smithy-security/smithy/sdk/component"
	ocsffindinginfov1 "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsfv1 "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/smithy-security/smithy/components/scanners/osv-scanner/pkg/config"
)

// Transformer will convert the output of OSV scanner into an OSCF vulnerability
// findings
type Transformer struct {
	cfg config.Config
}

type DatabaseSpecificInfo struct {
	CWEIDs   []string `json:"cwe_ids"`
	Severity string   `json:"severity"`
}

// New returns a configured instane of the Parser from OSV scanner results
// into OCSF VulnerabilityFindings
func New(cfg config.Config) (Transformer, error) {
	return Transformer{cfg: cfg}, nil
}

// Transform receives the results of the OSV scanner and converts them into
// OCSF vulnerabilities
func (t Transformer) Transform(
	ctx context.Context,
	vulns models.VulnerabilityResults,
) ([]*ocsfv1.VulnerabilityFinding, error) {
	targetMetadata := component.TargetMetadataFromCtx(ctx)
	if targetMetadata == nil {
		return nil, errors.New("no target metadata found")
	}

	vulnFindings := []*ocsfv1.VulnerabilityFinding{}

	for _, result := range vulns.Results {
		cleanFilePath, err := filepath.Rel(t.cfg.Root, result.Source.Path)
		if err != nil {
			return nil, errors.Errorf("could not create relative path: %w", err)
		}
		baseName := filepath.Base(cleanFilePath)

		dependencyReport, err := t.analyseDependencyFile(result.Source.Path)
		if err != nil {
			componentlogger.
				LoggerFromContext(ctx).
				Error(
					"could not analyse dependency file",
					slog.String("err", err.Error()),
				)
		}

		for _, pkg := range result.Packages {
			// A single package can have multiple vulnerabilities, so we iterate again
			// and create one vulnerability finding per vulnerability listed
			for _, vuln := range pkg.Vulnerabilities {
				lines := t.findDependencyDeclaration(
					pkg.Package.Name,
					pkg.Package.Version,
					dependencyReport,
				)

				// Determine the primary vulnerability ID. if it's not a CVE,
				// check the secondary IDs if there is a CVE ID.
				vulnID := vuln.ID
				if len(vuln.Aliases) > 0 && !strings.HasPrefix(strings.ToLower(vulnID), "cve") {
					vulnID = ""

					// Check aliases for a CVE ID
					for _, alias := range vuln.Aliases {
						if strings.HasPrefix(strings.ToLower(alias), "cve") {
							vulnID = alias
							break
						}
					}
				}

				severity := t.extractSeverity(ctx, vuln)

				for _, line := range lines {
					marshaledDataSource, err := protojson.Marshal(&ocsffindinginfov1.DataSource{
						TargetType:         ocsffindinginfov1.DataSource_TARGET_TYPE_REPOSITORY,
						SourceCodeMetadata: targetMetadata.SourceCodeMetadata,
						Uri: &ocsffindinginfov1.DataSource_URI{
							UriSchema: ocsffindinginfov1.DataSource_URI_SCHEMA_FILE,
							Path:      cleanFilePath,
						},
						LocationData: &ocsffindinginfov1.DataSource_FileFindingLocationData_{
							FileFindingLocationData: &ocsffindinginfov1.DataSource_FileFindingLocationData{
								StartLine: uint32(line),
								EndLine:   uint32(line),
							},
						},
					})
					if err != nil {
						return nil, errors.Errorf("could not marshal datasource: %w", err)
					}

					ocsfVulnFinding := &ocsfv1.VulnerabilityFinding{
						FindingInfo: &ocsfv1.FindingInfo{
							Uid:   vulnID,
							Title: vuln.Summary,
							Desc:  &vuln.Details,
							DataSources: []string{
								string(marshaledDataSource),
							},
							ProductUid: utils.Ptr("osv-scanner"),
						},
						Vulnerabilities: []*ocsfv1.Vulnerability{
							{
								Title: utils.Ptr(vuln.Summary),
								Desc:  &vuln.Details,
								AffectedCode: []*ocsfv1.AffectedCode{
									{
										File: &ocsfv1.File{
											Name: baseName,
											Path: &cleanFilePath,
										},
										StartLine: utils.Ptr(int32(line)),
										EndLine:   utils.Ptr(int32(line)),
									},
								},
								AffectedPackages: []*ocsfv1.AffectedPackage{
									{
										Name:    pkg.Package.Name,
										Version: pkg.Package.Version,
									},
								},
								Cve: &ocsfv1.Cve{
									Uid: vulnID,
								},
								Severity:   severity,
								VendorName: utils.Ptr("osv-scanner"),
							},
						},
					}

					vulnFindings = append(vulnFindings, ocsfVulnFinding)
				}
			}
		}
	}

	return vulnFindings, nil
}

func (t Transformer) extractSeverity(
	ctx context.Context,
	vuln osvschema.Vulnerability,
) *string {
	var (
		parsingErrs error
		rating      string
	)

	for i := 0; i < len(vuln.Severity) && rating == ""; i++ {
		severity := vuln.Severity[i]

		switch severity.Type {
		case osvschema.SeverityCVSSV4:
			parsedVector, err := gocvss40.ParseVector(severity.Score)
			if err != nil {
				parsingErrs = errors.Join(
					parsingErrs,
					errors.Errorf("could not parse CVSS 4.0 vector: %w", err),
				)

				continue
			}

			score := parsedVector.Score()
			rating, err = gocvss40.Rating(score)
			if err != nil {
				parsingErrs = errors.Join(
					parsingErrs,
					errors.Errorf("could not produce severity rating of CVSS 4.0 vector: %w", err))
			}

		case osvschema.SeverityCVSSV3:
			var err error
			if strings.HasPrefix(severity.Score, "CVSS:3.0") {
				var parsedVector *gocvss30.CVSS30
				parsedVector, err = gocvss30.ParseVector(severity.Score)
				if err == nil {
					rating, err = gocvss30.Rating(parsedVector.BaseScore())
				}
			} else if strings.HasPrefix(severity.Score, "CVSS:3.1") {
				var parsedVector *gocvss31.CVSS31
				parsedVector, err = gocvss31.ParseVector(severity.Score)
				if err == nil {
					rating, err = gocvss31.Rating(parsedVector.BaseScore())
				}
			}

			if err != nil {
				parsingErrs = errors.Join(
					parsingErrs,
					errors.Errorf("could not parse CVSS 3.* vector: %w", err),
				)
			}

		case osvschema.SeverityCVSSV2:
			parsedVector, err := gocvss20.ParseVector(severity.Score)
			if err != nil {
				parsingErrs = errors.Join(
					parsingErrs,
					errors.Errorf("could not parse CVSS 2.0 vector: %w", err),
				)
			} else {
				// gocvss20 doesn't have a Rating function but all the other
				// parsers are doing the exact same caregorisation so just
				// re-use them
				rating, err = gocvss31.Rating(parsedVector.BaseScore())
			}

		default: // This is an Ubuntu priority
			parsingErrs = errors.Join(parsingErrs, errors.New("got an ubuntu priority"))
		}
	}

	if val, ok := vuln.DatabaseSpecific["severity"]; ok && rating == "" {
		if strVal, ok := val.(string); ok {
			rating = strVal
		}
	}

	switch strings.ToLower(rating) {
	case "none":
		return utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_OTHER.String())
	case "low":
		return utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_LOW.String())
	case "medium":
		return utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_MEDIUM.String())
	case "high":
		return utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_HIGH.String())
	case "critical":
		return utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_CRITICAL.String())
	}

	if parsingErrs != nil {
		logger := componentlogger.LoggerFromContext(ctx)
		logger.Error(
			"could not extract the severity from the results",
			slog.String("err", parsingErrs.Error()),
		)
	}

	return utils.Ptr(ocsfv1.VulnerabilityFinding_SEVERITY_ID_UNKNOWN.String())
}

// analyseDependencyFile will check the dependency file and if it can be
// analysed, it will return a report showing the lines where each dependency
// is listed
func (t Transformer) analyseDependencyFile(dependencyFile string) (languages.DependencyReport, error) {
	var analyser languages.DependencyAnalyser
	switch filepath.Base(dependencyFile) {
	case "go.mod":
		analyser = languages.GoModAnalyser{}
	case "mix.lock":
		analyser = languages.ElixirLockAnalyser{}
	case "package-lock.json":
		analyser = languages.JSPackageLockAnalyser{}
	}

	if utils.IsNil(analyser) {
		return languages.DependencyReport{}, nil
	}

	return analyser.Analyse(dependencyFile)
}

func (t Transformer) findDependencyDeclaration(
	packageName, packageVersion string,
	depRep languages.DependencyReport,
) []int {
	switch depRep.Language {
	case languages.GOLANG:
		if packageName == "stdlib" {
			return []int{depRep.LanguageVersionLine}
		}

		if !strings.HasPrefix(packageVersion, "v") {
			packageVersion = "v" + packageVersion
		}
	}

	dep := languages.Dependency{
		Name:    packageName,
		Version: packageVersion,
	}

	depLines, ok := depRep.Dependencies[dep]
	if ok {
		return depLines
	}

	depLines, ok = depRep.IndirectDependencies[dep]
	if ok {
		return depLines
	}

	depLines, ok = depRep.TestDependencies[dep]
	if ok {
		return depLines
	}

	depLines, ok = depRep.DevDependencies[dep]
	if ok {
		return depLines
	}

	return []int{0}
}
