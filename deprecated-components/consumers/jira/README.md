# Jira Consumer

The Jira Consumer allows you to publish Vulnerability Issues to your
organisation's Jira workspace straight from the Smithy pipeline results.
Result fields such as 'target', 'cvss', 'severity', can either
be written in the description or mapped to specific custom fields used by your
workspace.

## Setting Up

### Matching your Jira Workspace needs

All you need to edit is provide a sensible configuration in yaml format so it
can match your organisational needs. You should be thinking about what Jira
Issue Fields you expect the tool to fill in (such as Project Key, Issue Type,
and even custom fields used by your workspace).

The configuration has three components:

* defaultValues: Here you can specify fields with default values such as:
  Project Key, Issue Type, or even specific custom fields that your workspace
  uses.
* addToDescription: Here you can specify what fields from the Smithy Results you
  want written in the Issue's description.
* mappings: In case your organisation has specific fields for CVSS, Severity,
  etc, you can also map the smithy results straight to these fields.
  If not, you can just add them to the description (see the point above).

There are more instructions in [docs](/docs/examples/jira-project/pipelinerun)
file for how to format those three components.

### Authentication through the Jira API

Authentication details for the Jira API are passed as environment variables.
These can be set up in the pipeline.yaml file or in the Dockerfile.

```text
SMITHY_JIRA_USER="<user@email.com>"
SMITHY_JIRA_TOKEN="your api token"
SMITHY_JIRA_URL="domain your jira workspace is hosted on"
```

## Testing

The following command will test that the app and configuration is working
correctly:

```bash
go test ./components/consumers/jira/...`
```

## Flags

The consumer supports the following flags:

```bash
   --dry-run              For debugging. Tickets will not be created, but will be logged to stdout
   --raw                  If the non-enriched results should be used
   --allow-fp             Allows issues tagged as 'false positive' by the enricher to be created.
   --allow-duplicates     Allows issues tagged as 'duplicate' by the enricher to be created.
   --severity-threshold   Only issues equal or above this threshold will get published. {0: All, 1: Minor, 2: Moderate, 3: High, 4: Critical,   Default: 3}
```

## Configuration

Below is example configuration and an explanation of each field

```json
{
  "defaultValues": {
    "project": "TEST",
    "issueType": "Task",
    "customFields": null
  },
  "descriptionTemplate":"Smithy found '{{.RawIssue.Title}}' at '{{.RawIssue.Target}}', severity '{{.RawIssue.Severity}}', rule id: '{{.RawIssue.Type}}', CVSS '{{.RawIssue.Cvss}}' Confidence '{{.RawIssue.Confidence}}' Original Description: {{.RawIssue.Description}}, Cve {{.RawIssue.Cve}},\n{{ range $key,$element := .Annotations }}{{$key}}:{{$element}}\n{{end}}",
  "addToDescription": [
    "scan_start_time",
    "tool_name",
    "target",
    "type",
    "confidence_text",
    "annotations"
  ],
  "mappings": null
}
```

### "project"

The name of the Jira Project or Board

### "issueType"

Jira supports custom ticket types, the default ticket type is "Task" but you
can set any ticket type that your jira instance supports (e.g. "Vulnerability"
if you have configured a ticket type named "Vulnerability")

### customFields

Since Jira supports custom fields this describes what information from a smithy
issue should be mapped to a jira custom field. This element accepts:
A struct of:

* ID: the id of the custom field
* FieldType: one of "single-value" (this jira custom field accepts a string),
  "multi-value" (jira custom field is a drop down), "float"
  (custom field is a number), "simple-value" (your jira admin has set this
  custom field as a simple value, it's an alternative to single-value and try
  using this if single-value fails)
* Values: either an array of values or a single value depending on what
  FieldType is set to.

### addToDescription

An array of which smithy api fields to add to the jira ticket description.

### mappings

Not used for now, it's part of a yet-untested jira-to-smithy syncroniser which
makes jira into a more comprehensive vulnerability management platform.
If you need this please open a ticket.
