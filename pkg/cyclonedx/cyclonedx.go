package cyclonedx

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/go-errors/errors"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
)

// ToSmithy accepts a cycloneDX bom file and transforms to an array containing a singular v1.Issue.
// revive:disable:cognitive-complexity,cyclomatic High complexity score but
func ToSmithy(inFile []byte, format, targetOverride string) ([]*v1.Issue, error) {
	bom := new(cdx.BOM)
	var decoder cdx.BOMDecoder
	var issues []*v1.Issue
	switch format {
	case "json":
		decoder = cdx.NewBOMDecoder(bytes.NewReader(inFile), cdx.BOMFileFormatJSON)
	case "xml":
		decoder = cdx.NewBOMDecoder(bytes.NewReader(inFile), cdx.BOMFileFormatXML)
	default:
		return issues, errors.Errorf("%s, is not a supported BOM format, currently we support either 'json' or 'xml'", format)
	}

	if err := decoder.Decode(bom); err != nil {
		return issues, err
	}
	componentLen := 0
	if bom.Components != nil {
		componentLen = len(*bom.Components)
	}
	slog.Info(fmt.Sprintf("Successfully parsed CycloneDX BOM, recorded %d components", componentLen))

	buf := new(bytes.Buffer)
	// Encode the BOM
	err := cdx.NewBOMEncoder(buf, cdx.BOMFileFormatJSON).SetPretty(false).Encode(bom)
	if err != nil {
		return issues, err
	}
	result := strings.TrimSpace(buf.String())
	target := ""
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		if bom.Metadata.Component.BOMRef != "" {
			target = bom.Metadata.Component.BOMRef
		} else {
			target = bom.Metadata.Component.PackageURL
		}
	}
	if targetOverride != "" {
		target = targetOverride
	}

	return []*v1.Issue{
		{
			CycloneDXSBOM: &result,
			Target:        target,
			Type:          "SBOM",
			Title:         fmt.Sprintf("SBOM for %s", target),
			Severity:      v1.Severity_SEVERITY_INFO,
		},
	}, nil
}

// FromSmithy accepts an issue and transforms to a cyclonedx bom.
func FromSmithy(issue *v1.Issue) (*cdx.BOM, error) {
	bom := new(cdx.BOM)
	if issue.CycloneDXSBOM == nil || *issue.CycloneDXSBOM == "" {
		return bom, errors.Errorf("issue %s does not have an sbom", issue.Uuid)
	}
	decoder := cdx.NewBOMDecoder(bytes.NewReader([]byte(*issue.CycloneDXSBOM)), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return bom, err
	}
	return bom, nil
}
