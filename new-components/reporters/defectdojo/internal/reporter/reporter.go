package reporter

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"log"
	"log/slog"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/go-errors/errors"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/smithy-security/pkg/env"

	"github.com/smithy-security/smithy/new-components/reporters/defectdojo/internal/client"
	"github.com/smithy-security/smithy/new-components/reporters/defectdojo/internal/types"
	"github.com/smithy-security/smithy/sdk/component"
	vf "github.com/smithy-security/smithy/sdk/component/vulnerability-finding"
	ocsffindinginfo "github.com/smithy-security/smithy/sdk/gen/ocsf_ext/finding_info/v1"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

const (
	// DojoTimeFormat is the time format accepted by defect dojo.
	dojoTimeFormat = "2006-01-02"

	// DojoTestTimeFormat is the time format expected by defect dojo when creating a test.
	dojoTestTimeFormat = "2006-01-02T03:03"
)

var (
	//go:embed descriptionTemplate.tpl
	defaultDescriptionTemplate string
)

type (
	Conf struct {
		User       string
		Token      string
		URL        string
		ProductID  int32
		Template   string
		instanceID string
	}
	dojoLogger struct {
		conf   *Conf
		client *client.Client
	}
)

// NewConf returns a new configuration build from environment lookup.
func NewConf(envLoader env.Loader) (*Conf, error) {
	var envOpts = make([]env.ParseOption, 0)
	if envLoader != nil {
		envOpts = append(envOpts, env.WithLoader(envLoader))
	}

	instanceId, err := env.GetOrDefault(
		"SMITHY_INSTANCE_ID",
		"",
		append(envOpts, env.WithDefaultOnError(false))...,
	)
	if err != nil {
		return nil, errors.Errorf("could not get SMITHY_INSTANCE_ID: %w", err)
	}

	dojoUser, err := env.GetOrDefault(
		"DOJO_USER",
		"administrator",
		append(envOpts, env.WithDefaultOnError(false))...,
	)
	if err != nil {
		return nil, errors.Errorf("could not get env variable for DOJO_USER: %w", err)
	}

	dojoKey, err := env.GetOrDefault(
		"DOJO_API_KEY",
		"",
		append(envOpts, env.WithDefaultOnError(false))...,
	)
	if err != nil {
		return nil, errors.Errorf("could not get env variable for DOJO_API_KEY: %w", err)
	}

	dojoURL, err := env.GetOrDefault(
		"DOJO_API_URL",
		"",
		append(envOpts, env.WithDefaultOnError(false))...,
	)
	if err != nil {
		return nil, errors.Errorf("could not get env variable for DOJO_API_URL: %w", err)
	}
	if !strings.HasSuffix(dojoURL, "api/v2") {
		return nil, errors.Errorf("the variable DOJO_API_URL needs to end in 'api/v2'")
	}
	pID, err := env.GetOrDefault(
		"DOJO_PRODUCT_ID",
		"",
		append(envOpts, env.WithDefaultOnError(false))...,
	)
	if err != nil {
		return nil, errors.Errorf("could not get env variable for PRODUCT_ID: %w", err)
	}
	productID, err := strconv.ParseInt(pID, 32, 10)
	if err != nil {
		return nil, errors.Errorf("could not get productID, expected int received '%s', err:%w", pID, err)
	}

	return &Conf{
		User:       dojoUser,
		Token:      dojoKey,
		URL:        dojoURL,
		ProductID:  int32(productID),
		instanceID: instanceId,
	}, nil
}

// New returns a new DefectDojo reporter.
func New(conf *Conf, client *client.Client) (*dojoLogger, error) {
	if conf == nil {
		return nil, errors.New("reporter.New called with nil config, this is unsupported")
	}
	if client == nil {
		return nil, errors.New("reporter.New called with a nil client, this is unsupported")
	}
	return &dojoLogger{
		conf:   conf,
		client: client,
	}, nil
}

// Report logs the findings in json format.
func (d dojoLogger) Report(ctx context.Context, findings []*vf.VulnerabilityFinding) error {
	logger := component.
		LoggerFromContext(ctx).
		With(slog.Int("num_findings", len(findings)))

	if len(findings) == 0 {
		logger.Warn("received no findings")
		return nil
	}

	if err := d.handleResults(ctx, findings, findings[0].Finding.StartTimeDt); err != nil {
		logger.Error("could not contact DefectDojo, err:%w", err)
		return err
	}
	return nil
}

func (d dojoLogger) groupByVendor(findings []*vf.VulnerabilityFinding) (map[string][]*vf.VulnerabilityFinding, error) {
	result := map[string][]*vf.VulnerabilityFinding{}
	for _, f := range findings {
		currentVendorName := ""
		if len(f.Finding.Vulnerabilities) > 0 {
			currentVendorName = *f.Finding.Vulnerabilities[0].VendorName
			for _, v := range f.Finding.Vulnerabilities {
				if *v.VendorName != currentVendorName {
					return nil, errors.Errorf("there is a finding with vulnerabilities from multiple vendors this is unsupported")
				}
			}
			result[currentVendorName] = append(result[currentVendorName], f)
		}
	}
	return result, nil
}

func (d dojoLogger) handleResults(ctx context.Context, findings []*vf.VulnerabilityFinding, scanStartTime *timestamppb.Timestamp) error {
	vendoredFindings, err := d.groupByVendor(findings)
	if err != nil {
		return err
	}
	scanUUID := d.conf.instanceID
	if scanUUID == "" {
		return errors.Errorf("scan does not have a UUID, this is fatal")
	}

	if len(vendoredFindings) == 0 {
		slog.Warn("got called with 0 findings, exiting")
		return nil
	}

	startTime, err := getEngagementTime(scanStartTime, scanUUID)
	if err != nil {
		return err
	}
	engagement, err := d.client.CreateEngagement(ctx, scanUUID, startTime.Format(dojoTimeFormat), []string{"SmithyScan", d.conf.instanceID}, int32(d.conf.ProductID))
	if err != nil {
		return errors.Errorf("could not create engagement, err: %w", err)
	}

	for toolName, findings := range vendoredFindings {
		for _, finding := range findings {
			if finding.Finding.Vulnerabilities[0].VendorName == nil {
				return errors.Errorf("found finding without tooling info, this means there's a scanner that does not populate the Vulnerabilities[].VendorName field, this is a bug")
			}
			test, err := d.client.CreateTest(ctx, startTime.Format(dojoTestTimeFormat), toolName, "", []string{"SmithyScan", scanUUID}, engagement.ID)
			if err != nil {
				return errors.Errorf("could not create test in remote defectdojo, err: %w", err)
			}

			for _, vuln := range finding.Finding.Vulnerabilities {
				description, err := applyTemplate(finding, vuln)
				if err != nil {
					log.Fatal("Could not template finding", err)
				}
				duplicate := false
				for _, e := range finding.Finding.Enrichments {
					if e.Type != nil && ocsffindinginfo.Enrichment_EnrichmentType_value[*e.Type] == int32(ocsffindinginfo.Enrichment_ENRICHMENT_TYPE_DUPLICATION) {
						duplicate = true
					}
				}
				filePaths := makeFilePaths(vuln)
				falsePositive := false

				cweID := 0
				if vuln.Cwe != nil {
					c, err := strconv.ParseInt(vuln.Cwe.Uid, 10, 32)
					if err != nil {
						slog.Error("could not parse ", slog.String("cwe_id", vuln.Cwe.Uid))
						c = 0
					}
					cweID = int(int32(c))
				}
				active := !duplicate
				body := types.FindingCreateRequest{
					Tags:              []string{"SmithyScan", scanUUID, toolName},
					Date:              startTime.Format(dojoTimeFormat),
					Cwe:               int32(cweID),
					Line:              0,
					FilePath:          filePaths,
					Duplicate:         duplicate,
					FalseP:            falsePositive,
					Active:            active,
					Verified:          false,
					Test:              test.ID,
					Title:             *vuln.Title,
					Description:       *description,
					Severity:          severityToDojoSeverity(vuln.Severity),
					NumericalSeverity: severityIDToDojoNumericalSeverity(vuln.Severity),
					FoundBy:           []int32{d.client.UserID},
					UniqueIDFromTool:  finding.Finding.GetMetadata().GetEventCode(),
					VulnIDFromTool:    finding.Finding.GetMetadata().GetEventCode(),
				}
				_, err = d.client.CreateFinding(ctx, body)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func makeFilePaths(v *ocsf.Vulnerability) string {
	result := ""
	for i, p := range v.AffectedCode {
		if i == 0 {
			result = fmt.Sprintf("%s:%d-%d", *p.File.Path, *p.StartLine, *p.EndLine)
		} else {
			result = fmt.Sprintf("%s,%s:%d-%d", result, *p.File.Path, *p.StartLine, *p.EndLine)
		}
	}
	return result
}

func severityToDojoSeverity(severity *string) string {
	switch ocsf.VulnerabilityFinding_SeverityId_value[*severity] {
	case int32(ocsf.VulnerabilityFinding_SEVERITY_ID_INFORMATIONAL):
		return "Info"
	case int32(ocsf.VulnerabilityFinding_SEVERITY_ID_LOW):
		return "Low"
	case int32(ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM):
		return "Medium"
	case int32(ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH):
		return "High"
	case int32(ocsf.VulnerabilityFinding_SEVERITY_ID_CRITICAL):
		return "Critical"
	default:
		return "Info"
	}
}
func severityIDToDojoNumericalSeverity(severityID *string) string {
	switch ocsf.VulnerabilityFinding_SeverityId_value[*severityID] {
	case int32(ocsf.VulnerabilityFinding_SEVERITY_ID_INFORMATIONAL):
		return "S:I"
	case int32(ocsf.VulnerabilityFinding_SEVERITY_ID_LOW):
		return "S:L"
	case int32(ocsf.VulnerabilityFinding_SEVERITY_ID_MEDIUM):
		return "S:M"
	case int32(ocsf.VulnerabilityFinding_SEVERITY_ID_HIGH):
		return "S:H"
	case int32(ocsf.VulnerabilityFinding_SEVERITY_ID_CRITICAL):
		return "S:C"
	default:
		return "S:I"
	}
}

// applyTemplate applies the provided go template to the finding provided and returns the resulting str
func applyTemplate(finding *vf.VulnerabilityFinding, vulnerability *ocsf.Vulnerability) (*string, error) {
	type message struct {
		Vulnerability *ocsf.Vulnerability
		Finding       *ocsf.VulnerabilityFinding
	}
	findingDescriptionTemplate := defaultDescriptionTemplate

	tmpl, err := template.New("description").Parse(findingDescriptionTemplate)
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)

	err = tmpl.Execute(buf, message{
		Vulnerability: vulnerability,
		Finding:       finding.Finding,
	})
	if err != nil {
		return nil, err
	}
	res := buf.String()
	return &res, nil
}

func getEngagementTime(engagementTime *timestamppb.Timestamp, scanID string) (time.Time, error) {
	if engagementTime == nil || engagementTime.AsTime().IsZero() {
		return time.Now(), errors.Errorf("engagement time is zero for scan %s", scanID)

	}
	return engagementTime.AsTime(), nil
}
