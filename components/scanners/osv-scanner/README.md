# osv-scanner

This component implements a [scanner](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go)
that parses json reports output by [osv-scan](https://google.github.io/osv-scanner/) into [ocsf](https://github.com/ocsf) format.

## Environment variables

The component uses environment variables for configuration.

It requires the component
environment variables defined [here](https://github.com/smithy-security/smithy/blob/main/sdk/README.md#component) as well
as the following:

| Environment Variable     | Type   | Required | Default    | Description                                             |
|--------------------------|--------|----------|------------|---------------------------------------------------------|
| RAW\_OUT\_FILE\_PATH  | string | yes      | -          | The path where to find the osv-scan report                 |
| TARGET\_TYPE         | string | false    | repository | The type of target that was used to generate the report |

## Test data

The `results.json` file used in tests was generated with the following steps:
