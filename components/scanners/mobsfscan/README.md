# mobsfsan v0.4.5 Scanner

This component implements a [scanner](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go)
that parses [sarif](https://sarifweb.azurewebsites.net/) reports output
by [mobsfscan](https://github.com/MobSF/mobsfscan) into [ocsf](https://github.com/ocsf) format.

## Parser Environment variables

The component uses environment variables for configuration.

It requires the component
environment variables defined [here](https://github.com/smithy-security/smithy/blob/main/sdk/README.md#component) as well
as the following:

| Environment Variable     | Type   | Required | Default    | Description                                             |
|--------------------------|--------|----------|------------|---------------------------------------------------------|
| MOBSF\_RAW\_OUT\_FILE\_PATH  | string | yes      | -          | The path where to find the mobsf sarif report   |
