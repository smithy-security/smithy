# Credo

This component implements a [scanner](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go)
that parses json reports output by [credo](https://github.com/rrrene/credo/) into [ocsf](https://github.com/ocsf) format.

## Environment variables

The component uses environment variables for configuration.

It requires the component
environment variables defined [here](https://github.com/smithy-security/smithy/blob/main/sdk/README.md#component) as well
as the following:

| Environment Variable     | Type   | Required | Default    | Description                                             |
|--------------------------|--------|----------|------------|---------------------------------------------------------|
| CREDO\_RAW\_OUT\_FILE\_PATH  | string | yes      | -          | The path where to find the sarif report                 |
