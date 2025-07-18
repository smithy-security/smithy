package sarif

import (
	"regexp"
	"strings"

	sarif "github.com/smithy-security/pkg/sarif/spec/gen/sarif-schema/v2-1-0"
	"github.com/smithy-security/pkg/utils"
	ocsf "github.com/smithy-security/smithy/sdk/gen/ocsf_schema/v1"
)

var (
	cveRegExp = regexp.MustCompile(`((CVE|cve)-\d{4}-\d{4,7})`)
	cweRegex  = regexp.MustCompile(`(?i)CWE-\d{3,}`)
)

func extractCVE(rule sarif.ReportingDescriptor) *ocsf.Cve {
	var desc string
	if rule.FullDescription != nil {
		desc = rule.FullDescription.Text
	}

	if rule.Help != nil && desc == "" {
		desc = rule.Help.Text
	}

	var uid string
	if strings.HasPrefix(rule.Id, "CVE-") {
		uid = rule.Id
	}

	if uid == "" && rule.FullDescription != nil {
		uid = checkForCVE(rule.FullDescription.Text)
	}

	if uid == "" && rule.FullDescription != nil {
		uid = checkForCVE(optionalStr(rule.FullDescription.Markdown))
	}

	if uid == "" && rule.Help != nil {
		uid = checkForCVE(rule.Help.Text)
	}

	if uid == "" && rule.Help != nil {
		uid = checkForCVE(optionalStr(rule.Help.Markdown))
	}

	if uid == "" {
		return nil
	}

	uid = strings.ToUpper(uid)
	if desc == "" {
		return &ocsf.Cve{Uid: uid}
	}

	return &ocsf.Cve{
		Uid:  uid,
		Desc: &desc,
	}
}

func optionalStr(s *string) string {
	if s == nil {
		return ""
	}

	return *s
}

func checkForCVE(text string) string {
	match := cveRegExp.FindStringSubmatch(text)
	if len(match) > 1 {
		return match[1]
	}

	return ""
}

func extractCWE(
	ruleID string,
	taxasByCWEID map[string]sarif.ReportingDescriptor,
	ruleToTools map[string]sarif.ReportingDescriptor,
) *ocsf.Cwe {
	cwe := &ocsf.Cwe{}

	rule, ok := ruleToTools[ruleID]
	if !ok {
		return nil
	}

	for _, rel := range rule.Relationships {
		cwe.Uid = *rel.Target.Id
		taxa, ok := taxasByCWEID[cwe.Uid]
		if !ok {
			continue
		}
		cwe.SrcUrl = taxa.HelpUri
		if taxa.FullDescription != nil && taxa.FullDescription.Text != "" {
			cwe.Caption = utils.Ptr(taxa.FullDescription.Text)
		}
	}
	if cwe.Uid != "" {
		return cwe
	}
	// if all else fails try to match regexp with tags (semgrep, snyk and codeql do that)
	if rule.Properties != nil {
		for _, tag := range rule.Properties.Tags {
			matches := cweRegex.FindAllString(tag, -1)
			for _, match := range matches {
				if match != "" {
					cwe.Uid = strings.ReplaceAll(strings.ToLower(match), "cwe-", "")
					return cwe // we only care about 1, since ocsf only supports one cwe
				}
			}

		}
	}
	return nil // all failed, no cwe
}

func getRuleID(res *sarif.Result) *string {
	switch res.Rule {
	case nil:
		return res.RuleId
	default:
		switch {
		case res.Rule.Id != nil:
			return res.Rule.Id
		case res.Rule.Guid != nil:
			return res.Rule.Guid
		default:
			return nil
		}
	}
}
