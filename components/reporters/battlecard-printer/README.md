# Battlecard Printer Reporter

## Overview

The **battlecard-printer** is a Smithy reporter component that logs a summary of vulnerability findings in a concise "battlecard" format. It is designed to help teams quickly understand the results of security scans, highlighting key metrics such as total findings, enrichments, and findings by tool.

## Features

* Summarizes vulnerability findings from Smithy workflows
* Aggregates enrichments and findings by tool
* Outputs a human-readable battlecard report
* Integrates easily into Smithy workflows

## Usage

### Workflow Integration

To use the battlecard-printer in a Smithy workflow, add it as a reporter component in your workflow YAML:

```yaml
components:
  - component: file://components/targets/git-clone/component.yaml
  - component: file://components/scanners/mobsfscan/component.yaml
  - component: file://components/enrichers/custom-annotation/component.yaml
  - component: file://components/reporters/battlecard-printer/component.yaml
```

### Component Configuration

The component is defined as follows:

```yaml
name: battlecard-printer
description: "Logs a summary of vulnerability findings in a battlecard format."
type: reporter
steps:
  - name: battlecard-printer
    image: components/reporters/battlecard-printer
    executable: /bin/app
```

## Output Format

The battlecard-printer generates output similar to:

```
Battlecard Report
=================
Total Findings: 3
Enrichments:
  - bar: 1
  - foo: 1
Findings By Tool:
  - gosec: 2
  - trufflehog: 1
```

## How It Works

The reporter:

* Collects all findings from the workflow
* Aggregates enrichments (e.g., custom annotations)
* Counts findings per tool (e.g., gosec, trufflehog)
* Logs the summary using the Smithy logger

## Testing

Unit tests for the battlecard report generation can be found in:

* `internal/reporter/reporter_test.go`

These tests cover:

* Correct aggregation of findings and enrichments
* Output formatting

## Contributing

Contributions and improvements are welcome! Please submit issues or pull requests via GitHub.
