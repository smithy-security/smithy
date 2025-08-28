# nancy v1.0 Scanner

This component implements a [scanner](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go)
that parses json reports output by [nancy](https://github.com/securego/gosec) into [ocsf](https://github.com/ocsf) format.

## Environment variables

The component uses environment variables for configuration.

It requires the component
environment variables defined [here](https://github.com/smithy-security/smithy/blob/main/sdk/README.md#component) as well
as the following:

| Environment Variable     | Type   | Required | Default    | Description                                             |
|--------------------------|--------|----------|------------|---------------------------------------------------------|
| NANCY\_RAW\_OUT\_FILE\_PATH  | string | yes      | -          | The path where to find the gosec report                 |
| NANCY\_SCANNED\_PROJECT\_ROOT         | string | false    |  | The root of the project being scanned, used to find go.mod files and point at lines where fixes are needed |

## Test data

The `nancy.json` file used in tests was generated with the following steps:

* Cloning:

```shell
git clone https://github.com/smithy-security/e2e-monorepo
```

* Running nancy

```shell
cd $location-of-e2e-monorepo-or-any-vulnerable-go-application && go list -json -deps ./... | docker run -v `pwd`:/code -i docker.io/sonatypecommunity/nancy:v1.0.42-alpine  nancy sleuth -o json  > nancy.json

```
