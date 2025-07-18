# Custom Annotation Enricher

## Overview

The **custom-annotation** enricher is a Smithy component that allows you to add custom metadata (annotations) to vulnerability findings during a workflow. This is useful for tagging findings with additional context, such as environment, team, severity overrides, or any other custom information relevant to your organization.

## Features

* Adds custom annotations to findings
* Flexible input parameters for annotation names and values
* Integrates seamlessly into Smithy workflows

## Input Parameter Examples

The `params` section allows you to specify any number of custom annotations. Example:

```yaml
params:
  annotations: "environment:staging, owner:devops, ticket:JIRA-1234"
```

You can use any key-value pairs that make sense for your workflow. These will be added to each finding as enrichments.

## How It Works

The enricher reads the `annotations` input parameters and attaches them to each finding processed in the workflow. This metadata is then available to downstream reporters and other components.

## Testing

Unit tests for the custom-annotation enricher should cover:

* Correct attachment of annotations to findings
* Handling of various input parameter formats

## Contributing

Contributions are welcome! Please submit issues or pull requests via GitHub.
