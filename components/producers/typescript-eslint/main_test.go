package main

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	v1 "github.com/smithy-security/smithy/api/proto/v1"
	"github.com/smithy-security/smithy/components/producers"
	"github.com/smithy-security/smithy/components/producers/typescript-eslint/types"
	"github.com/smithy-security/smithy/pkg/testutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const exampleOutput = `[{"filePath":"%s",
"messages":[
	{"ruleId":"@typescript-eslint/explicit-module-boundary-types",
	"severity":1,
	"message":"Missing return type on function.",
	"line":1,
	"column":46,
	"nodeType":"ArrowFunctionExpression",
	"messageId":"missingReturnType",
	"endLine":2,"endColumn":104},

	{"ruleId":"jsdoc/require-jsdoc","severity":1,"message":"Missing JSDoc comment.",
	"line":3,"column":1,"nodeType":"FunctionDeclaration",
	"messageId":"missingJsDoc","endColumn":null,
	"fix":{"range":[890,890],"text":"/**\n *\n */\n"}}],

	"errorCount":0,"warningCount":2,
	"fixableErrorCount":0,
	"fixableWarningCount":1,
	"source":"import {withPrefix} from 'gatsby';\nimport React from 'react';\n\nimport {NavigationNode} from '../../../types';\n\nimport {PrimaryMenuLink} from '../../atoms/Links/PrimaryMenuLink';\n\nimport {SidebarNavigationSecondaryLinks} from './SidebarNavigationSecondaryLinks';\nimport {markStringForWrappingInNav} from './utils';\n\ninterface SidebarNavigationPrimaryLinksProps {\n  navNodes: NavigationNode[];\n  route: string;\n}\n\nexport const SidebarNavigationPrimaryLinks = ({navNodes, route}: SidebarNavigationPrimaryLinksProps) => (\n  <ol>\n    {navNodes.map(({link, title, children}) => (\n      <li key={link}>\n        <PrimaryMenuLink active={isActive(withPrefix(link), route)} route={encodeURI(withPrefix(link))}>\n          {markStringForWrappingInNav(title) || ''}\n        </PrimaryMenuLink>\n        <SidebarNavigationSecondaryLinks navNodes={children} route={route} />\n      </li>\n    ))}\n  </ol>\n);\n\nfunction isActive(link: string, route: string) {\n  const nodeIsActive = link === route?.split('#')[0];\n  const nodeChildIsActive = route?.startsWith(link);\n\n  return nodeIsActive || nodeChildIsActive;\n}\n",

	"usedDeprecatedRules":[{"ruleId":"jsx-a11y/accessible-emoji","replacedBy":[]},{"ruleId":"jsx-a11y/label-has-for","replacedBy":[]}	]
	}]`

var code = `some
vulnerable
typescript
or
javascript`

func TestParseIssues(t *testing.T) {
	f, err := testutil.CreateFile("tfsec_tests_vuln_code.js", code)
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(f.Name())

	var results []types.ESLintIssue
	err = json.Unmarshal([]byte(fmt.Sprintf(exampleOutput, f.Name())), &results)
	require.NoError(t, err)
	issues, err := parseIssues(results)
	require.NoError(t, err)

	expectedIssue := &v1.Issue{
		Target:         fmt.Sprintf("file://%s:1-2", f.Name()),
		Type:           "@typescript-eslint/explicit-module-boundary-types",
		Title:          "@typescript-eslint/explicit-module-boundary-types",
		Severity:       v1.Severity_SEVERITY_MEDIUM,
		Cvss:           0.0,
		Confidence:     v1.Confidence_CONFIDENCE_MEDIUM,
		Description:    "Missing return type on function.",
		ContextSegment: &code,
	}
	issue2 := &v1.Issue{
		Target:         fmt.Sprintf("file://%s:3-3", f.Name()),
		Type:           "jsdoc/require-jsdoc",
		Title:          "jsdoc/require-jsdoc",
		Severity:       v1.Severity_SEVERITY_MEDIUM,
		Cvss:           0.0,
		Confidence:     v1.Confidence_CONFIDENCE_MEDIUM,
		Description:    "Missing JSDoc comment.",
		ContextSegment: &code,
	}
	assert.Equal(t, expectedIssue, issues[0])
	assert.Equal(t, issue2, issues[1])
}

func TestEndToEndCLIWithJSON(t *testing.T) {
	err := producers.TestEndToEnd(t, "./examples/dvna.json", "./examples/dvna.pb")
	assert.NoError(t, err)
}
