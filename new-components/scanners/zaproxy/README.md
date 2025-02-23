# ZAP

This component implements an advanced [scanner](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go)
that orchestrates zaproxy/zap with a provided orchestration script, the generates and parses a [sarif](https://sarifweb.azurewebsites.net/) report into [ocsf](https://github.com/ocsf) format.

## Parser Environment variables

The component uses environment variables for configuration.

It requires the component
environment variables defined [here](https://github.com/smithy-security/smithy/blob/main/sdk/README.md#component) as well
as the following:

| Environment Variable     | Type   | Required | Default    | Description                                             |
|--------------------------|--------|----------|------------|---------------------------------------------------------|
| ZAP\_RAW\_OUT\_FILE\_PATH  | string | yes      | -          | The path where to find the zap sarif report   |
