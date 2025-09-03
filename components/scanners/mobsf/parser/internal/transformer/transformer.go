package transformer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-errors/errors"
	"github.com/jonboulle/clockwork"
	"github.com/smithy-security/pkg/env"
	"github.com/smithy-security/pkg/utils"
	"github.com/smithy-security/smithy/sdk/component"
	findinginfov1 "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
	componentlogger "github.com/smithy-security/smithy/sdk/logger"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type (
	// MobSFTransformerOption allows customising the transformer.
	MobSFTransformerOption func(g *mobSFTransformer) error

	mobSFTransformer struct {
		clock           clockwork.Clock
		rawOutFilePath  string
		baseLineFinding *ocsf.VulnerabilityFinding
	}
)

var (
	cweRE = regexp.MustCompile(`CWE-(\d+)`)
)

// MobSFTransformerWithClock allows customising the underlying clock.
func MobSFTransformerWithClock(clock clockwork.Clock) MobSFTransformerOption {
	return func(g *mobSFTransformer) error {
		if clock == nil {
			return errors.Errorf("invalid nil clock")
		}
		g.clock = clock
		return nil
	}
}

// MobSFRawOutFilePath allows customising the underlying raw out file path.
func MobSFRawOutFilePath(path string) MobSFTransformerOption {
	return func(g *mobSFTransformer) error {
		if path == "" {
			return errors.Errorf("invalid raw out file path")
		}
		g.rawOutFilePath = path
		return nil
	}
}

// New returns a new mobSF transformer.
func New(opts ...MobSFTransformerOption) (*mobSFTransformer, error) {
	rawOutFilePath, err := env.GetOrDefault(
		"MOBSF_RAW_OUT_FILE_PATH",
		"",
		env.WithDefaultOnError(true),
	)
	if err != nil {
		return nil, err
	}

	t := mobSFTransformer{
		rawOutFilePath: rawOutFilePath,
		clock:          clockwork.NewRealClock(),
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

// Transform transforms raw sarif findings into ocsf vulnerability findings.
func (g *mobSFTransformer) Transform(ctx context.Context) ([]*ocsf.VulnerabilityFinding, error) {
	logger := componentlogger.
		LoggerFromContext(ctx)

	logger.Debug("preparing to parse raw mobSF output...")

	b, err := os.ReadFile(g.rawOutFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.Errorf("raw output file '%s' not found", g.rawOutFilePath)
		}
		return nil, errors.Errorf("failed to read raw output file '%s': %w", g.rawOutFilePath, err)
	}
	var common CommonReport
	if err := json.Unmarshal(b, &common); err != nil {
		return nil, errors.Errorf("failed to unmarshal raw output: %w", err)
	}

	baseline, err := g.setBaseLineFinding(ctx)
	if err != nil {
		return nil, errors.Errorf("failed to set baseline finding: %w", err)
	}
	g.baseLineFinding = baseline

	var ocsfVulns []*ocsf.VulnerabilityFinding
	if strings.ToLower(common.AppType) == "apk" {
		ocsfVulns, err = g.parseAndroidMobSFRawOutput(ctx, b)
		if err != nil {
			return nil, errors.Errorf("failed to parse raw output file '%s': %w", g.rawOutFilePath, err)
		}
	} else if strings.ToLower(common.AppType) == "ipa" || strings.ToLower(common.AppType) == "swift" {
		ocsfVulns, err = g.parseiOSMobSFRawOutput(ctx, b)
		if err != nil {
			return nil, errors.Errorf("could not parse iOS MobSF output: %w", err)
		}
	} else {
		return nil, errors.Errorf("unsupported app type '%s'", common.AppType)
	}

	logger.Debug("successfully parsed", len(ocsfVulns), "findings from raw mobSF output")
	return ocsfVulns, nil
}

func (g *mobSFTransformer) setBaseLineFinding(ctx context.Context) (*ocsf.VulnerabilityFinding, error) {
	datasource, err := g.mapDataSource(ctx)
	if err != nil {
		return nil, errors.Errorf("failed to map data source: %w", err)
	}

	now := g.clock.Now().Unix()
	return &ocsf.VulnerabilityFinding{
		ActivityName: utils.Ptr(ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.String()),
		ActivityId:   ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE,
		CategoryUid:  ocsf.VulnerabilityFinding_CATEGORY_UID_FINDINGS,
		ClassUid:     ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING,
		ClassName:    utils.Ptr(ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.String()),
		Count:        utils.Ptr(int32(1)),
		FindingInfo: &ocsf.FindingInfo{
			CreatedTime:   utils.Ptr(now),
			DataSources:   []string{datasource},
			FirstSeenTime: utils.Ptr(now),
			LastSeenTime:  utils.Ptr(now),
			ModifiedTime:  utils.Ptr(now),
			ProductUid:    utils.Ptr("mobSF"),
		},
		StartTime: utils.Ptr(now),
		Status:    utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW.String()),
		StatusId:  utils.Ptr(ocsf.VulnerabilityFinding_STATUS_ID_NEW),
		Time:      now,
		TypeUid: int64(
			ocsf.VulnerabilityFinding_CLASS_UID_VULNERABILITY_FINDING.Number()*100 +
				ocsf.VulnerabilityFinding_ACTIVITY_ID_CREATE.Number(),
		),
	}, nil
}

func (g *mobSFTransformer) parseAndroidMobSFRawOutput(
	ctx context.Context,
	b []byte,
) ([]*ocsf.VulnerabilityFinding, error) {
	var androidReport AndroidReport
	if err := json.Unmarshal(b, &androidReport); err != nil {
		return nil, errors.Errorf("failed to unmarshal raw output: %w", err)
	}

	return g.convertAndroidReportToOCSF(ctx, &androidReport)
}

func (g *mobSFTransformer) convertAndroidReportToOCSF(
	ctx context.Context,
	report *AndroidReport,
) ([]*ocsf.VulnerabilityFinding, error) {
	var findings []*ocsf.VulnerabilityFinding

	// Appsec findings first
	appsecFindings := g.convertAppSecFindingsToOCSF(report.Appsec)
	findings = append(findings, appsecFindings...)

	// Certificate findings next
	for _, issues := range report.CertificateAnalysis.CertificateFindings {
		finding := g.convertCertificateFindingToOCSF(issues)
		findings = append(findings, finding)
	}

	// Binary analysis findings
	for _, binaryReport := range report.BinaryAnalysis {
		finding := g.convertBinaryAnalysisFindingToOCSF(
			binaryReport.Name,
			binaryReport.Fortify.Description,
			g.mobsfSeverityToOcsf(binaryReport.Fortify.Severity),
			"Test if binary is fortified",
		)
		findings = append(findings, finding)

		finding = g.convertBinaryAnalysisFindingToOCSF(
			binaryReport.Name,
			binaryReport.Nx.Description,
			g.mobsfSeverityToOcsf(binaryReport.Nx.Severity),
			"Test if binary has NX enabled",
		)
		findings = append(findings, finding)

		finding = g.convertBinaryAnalysisFindingToOCSF(
			binaryReport.Name,
			binaryReport.Pie.Description,
			g.mobsfSeverityToOcsf(binaryReport.Pie.Severity),
			"Test if binary has PIE enabled",
		)
		findings = append(findings, finding)

		finding = g.convertBinaryAnalysisFindingToOCSF(
			binaryReport.Name,
			binaryReport.RelocationReadonly.Description,
			g.mobsfSeverityToOcsf(binaryReport.RelocationReadonly.Severity),
			"Test if binary has RelRO enabled",
		)
		findings = append(findings, finding)

		finding = g.convertBinaryAnalysisFindingToOCSF(
			binaryReport.Name,
			binaryReport.Rpath.Description,
			g.mobsfSeverityToOcsf(binaryReport.Rpath.Severity),
			"Test if binary has RPATH enabled",
		)
		findings = append(findings, finding)

		finding = g.convertBinaryAnalysisFindingToOCSF(
			binaryReport.Name,
			binaryReport.Runpath.Description,
			g.mobsfSeverityToOcsf(binaryReport.Runpath.Severity),
			"Test if binary has Runpath enabled",
		)
		findings = append(findings, finding)

		finding = g.convertBinaryAnalysisFindingToOCSF(
			binaryReport.Name,
			binaryReport.StackCanary.Description,
			g.mobsfSeverityToOcsf(binaryReport.StackCanary.Severity),
			"Test if binary has Stack Canary enabled",
		)
		findings = append(findings, finding)

		finding = g.convertBinaryAnalysisFindingToOCSF(
			binaryReport.Name,
			binaryReport.Symbol.Description,
			g.mobsfSeverityToOcsf(binaryReport.Symbol.Severity),
			"Test if binary has Symbols Stripped",
		)
		findings = append(findings, finding)
	}

	// Code analysis findings
	for ruleName, finding := range report.CodeAnalysis.Findings {
		fileFindings, err := g.convertCodeFindingToOCSF(ctx, ruleName, finding)
		if err != nil {
			return nil, err
		}

		findings = append(findings, fileFindings...)
	}

	for _, url := range report.FirebaseUrls {
		finding := g.convertFirebaseFindingsToOCSF(url)
		findings = append(findings, finding)
	}

	for _, manifestFinding := range report.ManifestAnalysis.ManifestFindings {
		finding := g.convertManifestFindingToOCSF(manifestFinding)
		findings = append(findings, finding)
	}

	for _, networkSecurityFinding := range report.NetworkSecurity.NetworkFindings {
		finding := g.convertNetworkSecurityFindingToOCSF(networkSecurityFinding)
		findings = append(findings, finding)
	}
	return findings, nil
}

func (g *mobSFTransformer) mobsfSeverityToOcsf(severity string) ocsf.VulnerabilityFinding_SeverityId {
	switch strings.ToLower(severity) {
	case "high":
		return ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH
	case "medium", "warning":
		return ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM
	case "low", "info":
		return ocsf.VulnerabilityFinding_SEVERITY_ID_INFORMATIONAL
	case "secure":
		return ocsf.VulnerabilityFinding_SEVERITY_ID_OTHER
	default:
		slog.Warn("unknown severity level", "severity", severity)
		return ocsf.VulnerabilityFinding_SEVERITY_ID_UNKNOWN
	}
}

func (g *mobSFTransformer) convertAppSecFindingsToOCSF(finding Appsec) []*ocsf.VulnerabilityFinding {
	var findings []*ocsf.VulnerabilityFinding
	// Appsec findings first
	for _, issues := range finding.High {
		finding := g.convertMobSFFindingToOCSF(issues, ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH)
		findings = append(findings, finding)
	}

	for _, issues := range finding.Warning {
		finding := g.convertMobSFFindingToOCSF(issues, ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM)
		findings = append(findings, finding)
	}

	for _, issues := range finding.Info {
		finding := g.convertMobSFFindingToOCSF(issues, ocsf.VulnerabilityFinding_SEVERITY_ID_INFORMATIONAL)
		findings = append(findings, finding)
	}

	for _, issues := range finding.Secure {
		finding := g.convertMobSFFindingToOCSF(issues, ocsf.VulnerabilityFinding_SEVERITY_ID_OTHER)
		findings = append(findings, finding)
	}

	for _, issues := range finding.Hotspot {
		finding := g.convertMobSFFindingToOCSF(issues, ocsf.VulnerabilityFinding_SEVERITY_ID_OTHER)
		findings = append(findings, finding)
	}

	return findings
}

// convertCertificateFindingToOCSF converts a certificate finding to an OCSF VulnerabilityFinding.
// The finding is expected to be a slice of strings with the following format:
// [severity, title, description]
// However, the order of the strings may vary, so we need to determine which string is which.
// We do this by looking for keywords in the strings.
// The description is the longest string.
// The severity is the string that contains "high", "warning", or "info".
// The title is the remaining string.
func (g *mobSFTransformer) convertCertificateFindingToOCSF(finding []string) *ocsf.VulnerabilityFinding {
	var severity, title, description = finding[0], finding[0], finding[0]
	var descriptionIndex, severityIndex int

	if len(finding) != 3 {
		slog.Warn("unexpected certificate finding length", "length", len(finding), "finding", finding)
	}

	// the description is the longest string
	for i, str := range finding {
		if len(strings.TrimSpace(str)) > len(strings.TrimSpace(description)) {
			description = str
			descriptionIndex = i
		}
		// Determine severity based on proximity to keywords
		if strings.Contains(description, "high") {
			severityIndex = i
			severity = ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH.String()
		} else if strings.Contains(description, "warning") {
			severityIndex = i
			severity = ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM.String()
		} else if strings.Contains(description, "info") {
			severityIndex = i
			severity = ocsf.VulnerabilityFinding_SEVERITY_ID_INFORMATIONAL.String()
		}
	}
	// the title is the first string that is not the description or severity
	for i, str := range finding {
		if i != descriptionIndex && i != severityIndex {
			title = str
			break
		}
	}

	// Create a copy of the baseline finding
	vf := proto.Clone(g.baseLineFinding).(*ocsf.VulnerabilityFinding)
	vf.FindingInfo.Desc = utils.Ptr(description)
	vf.FindingInfo.Title = title
	vf.FindingInfo.Uid = title
	vf.Message = &description
	vf.Severity = utils.Ptr(severity)
	vf.SeverityId = ocsf.VulnerabilityFinding_SeverityId(ocsf.VulnerabilityFinding_SeverityId_value[severity])
	vf.Time = g.clock.Now().Unix()
	vf.Vulnerabilities = []*ocsf.Vulnerability{
		{
			Desc:          &description,
			FirstSeenTime: utils.Ptr(g.clock.Now().Unix()),
			LastSeenTime:  utils.Ptr(g.clock.Now().Unix()),
			Severity:      utils.Ptr(severity),
			Title:         &title,
			VendorName:    utils.Ptr("MobSF"),
		},
	}
	return vf

}

func (g *mobSFTransformer) convertMobSFFindingToOCSF(
	finding Finding,
	severity ocsf.VulnerabilityFinding_SeverityId,
) *ocsf.VulnerabilityFinding {
	// Create a copy of the baseline finding
	vf := proto.Clone(g.baseLineFinding).(*ocsf.VulnerabilityFinding)
	vf.FindingInfo.Desc = utils.Ptr(finding.Description)
	vf.FindingInfo.Title = finding.Title
	vf.FindingInfo.Uid = finding.Title
	vf.Message = &finding.Description
	vf.Severity = utils.Ptr(severity.String())
	vf.SeverityId = severity
	vf.Time = g.clock.Now().Unix()
	vf.Vulnerabilities = []*ocsf.Vulnerability{
		{
			Desc:          &finding.Description,
			FirstSeenTime: utils.Ptr(g.clock.Now().Unix()),
			LastSeenTime:  utils.Ptr(g.clock.Now().Unix()),
			Severity:      utils.Ptr(severity.String()),
			Title:         &finding.Title,
			VendorName:    utils.Ptr("MobSF"),
		},
	}
	return vf
}

func (g *mobSFTransformer) convertBinaryAnalysisFindingToOCSF(
	binaryName string,
	findingDescription string,
	severity ocsf.VulnerabilityFinding_SeverityId,
	title string,
) *ocsf.VulnerabilityFinding {
	// Create a copy of the baseline finding
	vf := proto.Clone(g.baseLineFinding).(*ocsf.VulnerabilityFinding)
	vf.FindingInfo.Desc = utils.Ptr(findingDescription)
	vf.FindingInfo.FirstSeenTime = utils.Ptr(g.clock.Now().Unix())
	vf.FindingInfo.LastSeenTime = utils.Ptr(g.clock.Now().Unix())
	vf.FindingInfo.ModifiedTime = utils.Ptr(g.clock.Now().Unix())
	vf.FindingInfo.ProductUid = utils.Ptr("mobSF")
	vf.FindingInfo.Title = title
	vf.FindingInfo.Uid = title
	vf.Severity = utils.Ptr(severity.String())
	vf.SeverityId = severity
	vf.Vulnerabilities = []*ocsf.Vulnerability{
		{
			AffectedCode: []*ocsf.AffectedCode{
				{
					File: &ocsf.File{
						Name: binaryName,
					},
				},
			},
			Desc:          utils.Ptr(findingDescription),
			FirstSeenTime: utils.Ptr(g.clock.Now().Unix()),
			LastSeenTime:  utils.Ptr(g.clock.Now().Unix()),
			Severity:      utils.Ptr(severity.String()),
			Title:         utils.Ptr(title),
			VendorName:    utils.Ptr("MobSF"),
		},
	}
	return vf
}

func (g *mobSFTransformer) convertCodeFindingToOCSF(
	ctx context.Context,
	ruleName string,
	finding CodeFinding,
) ([]*ocsf.VulnerabilityFinding, error) {
	vf, ok := proto.Clone(g.baseLineFinding).(*ocsf.VulnerabilityFinding)
	if !ok {
		return nil, errors.Errorf("there was an issue cloning base line finding: %v", vf)
	}

	// Extract CWE number from ruleName if present (e.g., "CWE-532: Insertion of Sensitive Information into Log File")
	var cweNumber string
	if matches := cweRE.FindStringSubmatch(ruleName); len(matches) == 2 {
		cweNumber = matches[1]
	}
	vf.Message = &finding.Metadata.Description
	vf.FindingInfo.Title = ruleName
	vf.FindingInfo.Uid = ruleName
	vf.FindingInfo.Desc = utils.Ptr(fmt.Sprintf("%s:%s", ruleName, finding.Metadata.Description))
	vf.Severity = utils.Ptr(g.mobsfSeverityToOcsf(finding.Metadata.Severity).String())
	vf.SeverityId = g.mobsfSeverityToOcsf(finding.Metadata.Severity)
	vf.Vulnerabilities = []*ocsf.Vulnerability{
		{
			Cwe: &ocsf.Cwe{
				Uid:     cweNumber,
				Caption: &finding.Metadata.Cwe,
			},
			Desc:          &finding.Metadata.Description,
			FirstSeenTime: utils.Ptr(g.clock.Now().Unix()),
			LastSeenTime:  utils.Ptr(g.clock.Now().Unix()),
			Severity:      utils.Ptr(g.mobsfSeverityToOcsf(finding.Metadata.Severity).String()),
			Title:         &ruleName,
			VendorName:    utils.Ptr("MobSF"),
			References:    []string{finding.Metadata.Ref},
		},
	}

	denormalisedFindings := []*ocsf.VulnerabilityFinding{}
	dataSource := component.TargetMetadataFromCtx(ctx)
	for filename, lines := range finding.Files {
		for _, line := range strings.Split(lines, ",") {
			intLine, err := strconv.Atoi(line)
			if err != nil {
				slog.Warn("failed to convert line number to int", "line", line, "error", err)
				continue
			}

			if intLine < 0 || intLine > math.MaxInt32 {
				slog.Warn("line number out of int32 bounds", "line", intLine)
				continue
			}

			denormalisedFinding, ok := proto.Clone(vf).(*ocsf.VulnerabilityFinding)
			if !ok {
				return nil, errors.Errorf("there was an issue cloning vulnerability finding: %v", denormalisedFinding)
			}

			contextualisedDataSource, ok := proto.Clone(dataSource).(*findinginfov1.DataSource)
			if !ok {
				return nil, errors.Errorf("could not clone data source: %s", dataSource.String())
			}

			contextualisedFilename := filename
			if contextualisedDataSource.Uri.Path != "" {
				contextualisedFilename = fmt.Sprintf("%s:%s", contextualisedDataSource.Uri.Path, filename)
			}

			denormalisedFinding.Vulnerabilities[0].AffectedCode = []*ocsf.AffectedCode{
				{
					File: &ocsf.File{
						Name: contextualisedFilename,
					},
					StartLine: utils.Ptr(int32(intLine)),
					EndLine:   utils.Ptr(int32(intLine)),
				},
			}

			contextualisedDataSource.Uri.Path = contextualisedFilename
			contextualisedDataSource.LocationData = &findinginfov1.DataSource_FileFindingLocationData_{
				FileFindingLocationData: &findinginfov1.DataSource_FileFindingLocationData{
					StartLine: uint32(intLine),
					EndLine:   uint32(intLine),
				},
			}

			marshaledDataSource, err := protojson.Marshal(contextualisedDataSource)
			if err != nil {
				return nil, errors.Errorf("could not marshal data source: %v", contextualisedDataSource)
			}

			denormalisedFinding.FindingInfo.DataSources[0] = string(marshaledDataSource)
			denormalisedFindings = append(denormalisedFindings, denormalisedFinding)
		}
	}

	return denormalisedFindings, nil
}

func (g *mobSFTransformer) convertFirebaseFindingsToOCSF(url FirebaseUrl) *ocsf.VulnerabilityFinding {
	vf := proto.Clone(g.baseLineFinding).(*ocsf.VulnerabilityFinding)
	vf.FindingInfo.Desc = utils.Ptr(url.Description)
	vf.FindingInfo.Title = url.Title
	vf.FindingInfo.Uid = url.Title
	vf.Message = &url.Description

	severity := g.mobsfSeverityToOcsf(url.Severity)
	vf.Severity = utils.Ptr(severity.String())
	vf.SeverityId = severity
	vf.Vulnerabilities = []*ocsf.Vulnerability{
		{
			Desc:          &url.Description,
			FirstSeenTime: utils.Ptr(g.clock.Now().Unix()),
			LastSeenTime:  utils.Ptr(g.clock.Now().Unix()),
			Severity:      utils.Ptr(severity.String()),
			Title:         &url.Title,
			VendorName:    utils.Ptr("MobSF"),
		},
	}

	return vf
}

func (g *mobSFTransformer) convertManifestFindingToOCSF(finding ManifestFinding) *ocsf.VulnerabilityFinding {
	vf := proto.Clone(g.baseLineFinding).(*ocsf.VulnerabilityFinding)
	vf.FindingInfo.Desc = utils.Ptr(finding.Description)
	vf.FindingInfo.Title = finding.Title
	vf.FindingInfo.Uid = finding.Rule
	vf.Message = &finding.Description

	severity := g.mobsfSeverityToOcsf(finding.Severity)
	vf.Severity = utils.Ptr(severity.String())
	vf.SeverityId = severity
	vf.Vulnerabilities = []*ocsf.Vulnerability{
		{
			Desc:          &finding.Description,
			FirstSeenTime: utils.Ptr(g.clock.Now().Unix()),
			LastSeenTime:  utils.Ptr(g.clock.Now().Unix()),
			Severity:      utils.Ptr(severity.String()),
			Title:         &finding.Title,
			VendorName:    utils.Ptr("MobSF"),
		},
	}
	return vf
}

func (g *mobSFTransformer) convertNetworkSecurityFindingToOCSF(finding NetworkFinding) *ocsf.VulnerabilityFinding {
	vf := proto.Clone(g.baseLineFinding).(*ocsf.VulnerabilityFinding)
	vf.FindingInfo.Desc = utils.Ptr(finding.Description)
	vf.FindingInfo.Title = finding.Description
	vf.FindingInfo.Uid = finding.Description
	vf.Message = &finding.Description

	severity := g.mobsfSeverityToOcsf(finding.Severity)
	vf.Severity = utils.Ptr(severity.String())
	vf.SeverityId = severity
	vf.Vulnerabilities = []*ocsf.Vulnerability{
		{
			Desc:          &finding.Description,
			FirstSeenTime: utils.Ptr(g.clock.Now().Unix()),
			LastSeenTime:  utils.Ptr(g.clock.Now().Unix()),
			Severity:      utils.Ptr(severity.String()),
			Title:         &finding.Description,
			VendorName:    utils.Ptr("MobSF"),
		},
	}
	return vf
}

func (g *mobSFTransformer) mapDataSource(ctx context.Context) (string, error) {
	targetMetadata := component.TargetMetadataFromCtx(ctx)
	toBytes, err := protojson.Marshal(targetMetadata)
	if err != nil {
		return "", errors.Errorf("failed to marshal data source to JSON err:%w", err)
	}

	return string(toBytes), nil
}

func (g *mobSFTransformer) convertAtsFindingToOCSF(finding AtsFinding) *ocsf.VulnerabilityFinding {
	vf := proto.Clone(g.baseLineFinding).(*ocsf.VulnerabilityFinding)
	vf.FindingInfo.Desc = utils.Ptr(finding.Description)
	vf.FindingInfo.Title = finding.Issue
	vf.FindingInfo.Uid = finding.Issue
	vf.Message = &finding.Description
	vf.Severity = utils.Ptr(g.mobsfSeverityToOcsf(finding.Severity).String())
	vf.SeverityId = g.mobsfSeverityToOcsf(finding.Severity)
	vf.Vulnerabilities = []*ocsf.Vulnerability{
		{
			Desc:          &finding.Description,
			FirstSeenTime: utils.Ptr(g.clock.Now().Unix()),
			LastSeenTime:  utils.Ptr(g.clock.Now().Unix()),
			Severity:      utils.Ptr(g.mobsfSeverityToOcsf(finding.Severity).String()),
			Title:         &finding.Issue,
			VendorName:    utils.Ptr("MobSF"),
		},
	}
	return vf
}

func (g *mobSFTransformer) convertIOSBinaryFindingToOCSF(
	ruleID string,
	finding IosBinaryFinding,
) *ocsf.VulnerabilityFinding {
	vf := proto.Clone(g.baseLineFinding).(*ocsf.VulnerabilityFinding)

	var cweNumber string
	if matches := cweRE.FindStringSubmatch(finding.Cwe); len(matches) == 2 {
		cweNumber = matches[1]
	}

	vf.FindingInfo.Title = ruleID
	vf.FindingInfo.Uid = ruleID
	vf.FindingInfo.Desc = utils.Ptr(fmt.Sprintf("%s: %s", ruleID, finding.DetailedDesc))
	vf.Severity = utils.Ptr(g.mobsfSeverityToOcsf(finding.Severity).String())
	vf.SeverityId = g.mobsfSeverityToOcsf(finding.Severity)
	vf.Message = &finding.DetailedDesc
	vf.Vulnerabilities = []*ocsf.Vulnerability{
		{
			Cwe: &ocsf.Cwe{
				Uid:     cweNumber,
				Caption: &finding.Cwe,
			},
			Desc:          &finding.DetailedDesc,
			FirstSeenTime: utils.Ptr(g.clock.Now().Unix()),
			LastSeenTime:  utils.Ptr(g.clock.Now().Unix()),
			Severity:      utils.Ptr(g.mobsfSeverityToOcsf(finding.Severity).String()),
			Title:         &ruleID,
			VendorName:    utils.Ptr("MobSF"),
		},
	}
	return vf
}

func (g *mobSFTransformer) convertDylibFindingToOCSF(dylib IosLibAnalysis) []*ocsf.VulnerabilityFinding {
	findings := []*ocsf.VulnerabilityFinding{}
	// arc
	vf := proto.Clone(g.baseLineFinding).(*ocsf.VulnerabilityFinding)
	vf.FindingInfo.Desc = utils.Ptr(dylib.Arc.Description)
	vf.FindingInfo.Title = dylib.Arc.Description
	vf.FindingInfo.Uid = dylib.Arc.Description
	vf.Message = &dylib.Arc.Description
	vf.Severity = utils.Ptr(g.mobsfSeverityToOcsf(dylib.Arc.Severity).String())
	vf.SeverityId = g.mobsfSeverityToOcsf(dylib.Arc.Severity)
	vf.Vulnerabilities = []*ocsf.Vulnerability{
		{
			AffectedPackages: []*ocsf.AffectedPackage{
				{
					Name: dylib.Name,
				},
			},
			Desc:          &dylib.Arc.Description,
			FirstSeenTime: utils.Ptr(g.clock.Now().Unix()),
			LastSeenTime:  utils.Ptr(g.clock.Now().Unix()),
			Severity:      utils.Ptr(g.mobsfSeverityToOcsf(dylib.Arc.Severity).String()),
			Title:         &dylib.Arc.Description,
			VendorName:    utils.Ptr("MobSF"),
		},
	}
	findings = append(findings, vf)

	// code_signing
	vf = proto.Clone(g.baseLineFinding).(*ocsf.VulnerabilityFinding)
	vf.FindingInfo.Desc = utils.Ptr(dylib.CodeSignature.Description)
	vf.FindingInfo.Title = dylib.CodeSignature.Description
	vf.FindingInfo.Uid = dylib.CodeSignature.Description
	vf.Message = &dylib.CodeSignature.Description
	vf.Severity = utils.Ptr(g.mobsfSeverityToOcsf(dylib.CodeSignature.Severity).String())
	vf.SeverityId = g.mobsfSeverityToOcsf(dylib.CodeSignature.Severity)
	vf.Vulnerabilities = []*ocsf.Vulnerability{
		{
			AffectedPackages: []*ocsf.AffectedPackage{
				{
					Name: dylib.Name,
				},
			},
			Desc:          &dylib.CodeSignature.Description,
			FirstSeenTime: utils.Ptr(g.clock.Now().Unix()),
			LastSeenTime:  utils.Ptr(g.clock.Now().Unix()),
			Severity:      utils.Ptr(g.mobsfSeverityToOcsf(dylib.CodeSignature.Severity).String()),
			Title:         &dylib.CodeSignature.Description,
			VendorName:    utils.Ptr("MobSF"),
		},
	}
	findings = append(findings, vf)

	// encryption
	vf = proto.Clone(g.baseLineFinding).(*ocsf.VulnerabilityFinding)
	vf.FindingInfo.Desc = utils.Ptr(dylib.Encrypted.Description)
	vf.FindingInfo.Title = dylib.Encrypted.Description
	vf.FindingInfo.Uid = dylib.Encrypted.Description
	vf.Message = &dylib.Encrypted.Description
	vf.Severity = utils.Ptr(g.mobsfSeverityToOcsf(dylib.Encrypted.Severity).String())
	vf.SeverityId = g.mobsfSeverityToOcsf(dylib.Encrypted.Severity)
	vf.Vulnerabilities = []*ocsf.Vulnerability{
		{
			AffectedPackages: []*ocsf.AffectedPackage{
				{
					Name: dylib.Name,
				},
			},
			Desc:          &dylib.Encrypted.Description,
			FirstSeenTime: utils.Ptr(g.clock.Now().Unix()),
			LastSeenTime:  utils.Ptr(g.clock.Now().Unix()),
			Severity:      utils.Ptr(g.mobsfSeverityToOcsf(dylib.Encrypted.Severity).String()),
			Title:         &dylib.Encrypted.Description,
			VendorName:    utils.Ptr("MobSF"),
		},
	}
	findings = append(findings, vf)

	// nx
	vf = proto.Clone(g.baseLineFinding).(*ocsf.VulnerabilityFinding)
	vf.FindingInfo.Desc = utils.Ptr(dylib.Nx.Description)
	vf.FindingInfo.Title = dylib.Nx.Description
	vf.FindingInfo.Uid = dylib.Nx.Description
	vf.Message = &dylib.Nx.Description
	vf.Severity = utils.Ptr(g.mobsfSeverityToOcsf(dylib.Nx.Severity).String())
	vf.SeverityId = g.mobsfSeverityToOcsf(dylib.Nx.Severity)
	vf.Vulnerabilities = []*ocsf.Vulnerability{
		{
			AffectedPackages: []*ocsf.AffectedPackage{
				{
					Name: dylib.Name,
				},
			},
			Desc:          &dylib.Nx.Description,
			FirstSeenTime: utils.Ptr(g.clock.Now().Unix()),
			LastSeenTime:  utils.Ptr(g.clock.Now().Unix()),
			Severity:      utils.Ptr(g.mobsfSeverityToOcsf(dylib.Nx.Severity).String()),
			Title:         &dylib.Nx.Description,
			VendorName:    utils.Ptr("MobSF"),
		},
	}
	findings = append(findings, vf)

	// pie
	vf = proto.Clone(g.baseLineFinding).(*ocsf.VulnerabilityFinding)
	vf.FindingInfo.Desc = utils.Ptr(dylib.Pie.Description)
	vf.FindingInfo.Title = dylib.Pie.Description
	vf.FindingInfo.Uid = dylib.Pie.Description
	vf.Message = &dylib.Pie.Description
	vf.Severity = utils.Ptr(g.mobsfSeverityToOcsf(dylib.Pie.Severity).String())
	vf.SeverityId = g.mobsfSeverityToOcsf(dylib.Pie.Severity)
	vf.Vulnerabilities = []*ocsf.Vulnerability{
		{
			AffectedPackages: []*ocsf.AffectedPackage{
				{
					Name: dylib.Name,
				},
			},
			Desc:          &dylib.Pie.Description,
			FirstSeenTime: utils.Ptr(g.clock.Now().Unix()),
			LastSeenTime:  utils.Ptr(g.clock.Now().Unix()),
			Severity:      utils.Ptr(g.mobsfSeverityToOcsf(dylib.Pie.Severity).String()),
			Title:         &dylib.Pie.Description,
			VendorName:    utils.Ptr("MobSF"),
		},
	}
	findings = append(findings, vf)

	// rpath
	vf = proto.Clone(g.baseLineFinding).(*ocsf.VulnerabilityFinding)
	vf.FindingInfo.Desc = utils.Ptr(dylib.Rpath.Description)
	vf.FindingInfo.Title = dylib.Rpath.Description
	vf.FindingInfo.Uid = dylib.Rpath.Description
	vf.Message = &dylib.Rpath.Description
	vf.Severity = utils.Ptr(g.mobsfSeverityToOcsf(dylib.Rpath.Severity).String())
	vf.SeverityId = g.mobsfSeverityToOcsf(dylib.Rpath.Severity)
	vf.Vulnerabilities = []*ocsf.Vulnerability{
		{
			AffectedPackages: []*ocsf.AffectedPackage{
				{
					Name: dylib.Name,
				},
			},
			Desc:          &dylib.Rpath.Description,
			FirstSeenTime: utils.Ptr(g.clock.Now().Unix()),
			LastSeenTime:  utils.Ptr(g.clock.Now().Unix()),
			Severity:      utils.Ptr(g.mobsfSeverityToOcsf(dylib.Rpath.Severity).String()),
			Title:         &dylib.Rpath.Description,
			VendorName:    utils.Ptr("MobSF"),
		},
	}
	findings = append(findings, vf)

	// stack_canary
	vf = proto.Clone(g.baseLineFinding).(*ocsf.VulnerabilityFinding)
	vf.FindingInfo.Desc = utils.Ptr(dylib.StackCanary.Description)
	vf.FindingInfo.Title = dylib.StackCanary.Description
	vf.FindingInfo.Uid = dylib.StackCanary.Description
	vf.Message = &dylib.StackCanary.Description
	vf.Severity = utils.Ptr(g.mobsfSeverityToOcsf(dylib.StackCanary.Severity).String())
	vf.SeverityId = g.mobsfSeverityToOcsf(dylib.StackCanary.Severity)
	vf.Vulnerabilities = []*ocsf.Vulnerability{
		{
			AffectedPackages: []*ocsf.AffectedPackage{
				{
					Name: dylib.Name,
				},
			},
			Desc:          &dylib.StackCanary.Description,
			FirstSeenTime: utils.Ptr(g.clock.Now().Unix()),
			LastSeenTime:  utils.Ptr(g.clock.Now().Unix()),
			Severity:      utils.Ptr(g.mobsfSeverityToOcsf(dylib.StackCanary.Severity).String()),
			Title:         &dylib.StackCanary.Description,
			VendorName:    utils.Ptr("MobSF"),
		},
	}
	findings = append(findings, vf)

	// symbol
	vf = proto.Clone(g.baseLineFinding).(*ocsf.VulnerabilityFinding)
	vf.FindingInfo.Desc = utils.Ptr(dylib.Symbol.Description)
	vf.FindingInfo.Title = dylib.Symbol.Description
	vf.FindingInfo.Uid = dylib.Symbol.Description
	vf.Message = &dylib.Symbol.Description
	vf.Severity = utils.Ptr(g.mobsfSeverityToOcsf(dylib.Symbol.Severity).String())
	vf.SeverityId = g.mobsfSeverityToOcsf(dylib.Symbol.Severity)
	vf.Vulnerabilities = []*ocsf.Vulnerability{
		{
			AffectedPackages: []*ocsf.AffectedPackage{
				{
					Name: dylib.Name,
				},
			},
			Desc:          &dylib.Symbol.Description,
			FirstSeenTime: utils.Ptr(g.clock.Now().Unix()),
			LastSeenTime:  utils.Ptr(g.clock.Now().Unix()),
			Severity:      utils.Ptr(g.mobsfSeverityToOcsf(dylib.Symbol.Severity).String()),
			Title:         &dylib.Symbol.Description,
			VendorName:    utils.Ptr("MobSF"),
		},
	}
	findings = append(findings, vf)

	return findings
}

func (g *mobSFTransformer) parseiOSMobSFRawOutput(
	ctx context.Context,
	rawOutput []byte,
) ([]*ocsf.VulnerabilityFinding, error) {
	var report IOsReport
	if err := json.Unmarshal(rawOutput, &report); err != nil {
		return nil, errors.Errorf("failed to unmarshal MobSF iOS output: %w", err)
	}

	var findings []*ocsf.VulnerabilityFinding
	// Appsec findings first
	appsecFindings := g.convertAppSecFindingsToOCSF(report.Appsec)
	findings = append(findings, appsecFindings...)

	// ATS findings next
	for _, issues := range report.AtsAnalysis.AtsFindings {
		finding := g.convertAtsFindingToOCSF(issues)
		findings = append(findings, finding)
	}

	// Binary analysis findings
	for ruleID, binaryReport := range report.BinaryAnalysis.Findings {
		finding := g.convertIOSBinaryFindingToOCSF(ruleID, binaryReport)
		findings = append(findings, finding)
	}

	// Code analysis findings
	for ruleName, finding := range report.CodeAnalysis.Findings {
		fileFindings, err := g.convertCodeFindingToOCSF(ctx, ruleName, finding)
		if err != nil {
			return nil, err
		}

		findings = append(findings, fileFindings...)
	}

	for _, dyLib := range report.DylibAnalysis {
		libraryFindings := g.convertDylibFindingToOCSF(dyLib)
		findings = append(findings, libraryFindings...)
	}

	for _, frameworkFinding := range report.FrameworkAnalysis {
		libraryFindings := g.convertDylibFindingToOCSF(frameworkFinding)
		findings = append(findings, libraryFindings...)
	}

	machoFindings := g.convertDylibFindingToOCSF(report.MachoAnalysis)
	findings = append(findings, machoFindings...)

	return findings, nil
}
