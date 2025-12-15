# Snyk-SBOM

This component implements a [scanner](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go)
that uses the command `snyk sbom` to generate an sbom for any tech snyk supports and send it to a waiting Dependency Track.
This component does not do any other processing at this time.

## Parser Environment variables

The component uses environment variables for configuration.

It requires the component
environment variables defined [here](https://github.com/smithy-security/smithy/blob/main/sdk/README.md#component) as well
as the following:

| Environment Variable     | Type   | Required | Default    | Description                                             |
|--------------------------|--------|----------|------------|---------------------------------------------------------|
| RAW\_OUT\_FILE\_PATH  | string | yes      | -          | The path where to find the snyk sarif report   |
