# GitHub CodeQL

This component implements a [scanner](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go)
the GitHub CodeQL binary against a repository to produce SAST findings
and parses them to [ocsf](https://github.com/ocsf) format.

## Environment variables

The component uses environment variables for configuration.

It requires the component
environment variables defined [here](https://github.com/smithy-security/smithy/blob/main/sdk/README.md#component) as well
as the following:

| Environment Variable     | Type   | Required | Default    | Description                          |
|--------------------------|--------|----------|------------|--------------------------------------|
| CODEQL\_RAW\_OUT\_FILE\_GLOB  | string | yes      | -          | The path where to output findings to |
