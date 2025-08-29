# gosec v2.15.0 Scanner

This component implements a [scanner](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go)
that parses [sarif](https://sarifweb.azurewebsites.net/) reports output
by [gosec](https://github.com/securego/gosec) into [ocsf](https://github.com/ocsf) format.

## Environment variables

The component uses environment variables for configuration.

It requires the component
environment variables defined [here](https://github.com/smithy-security/smithy/blob/main/sdk/README.md#component) as well
as the following:

| Environment Variable     | Type   | Required | Default    | Description                                             |
|--------------------------|--------|----------|------------|---------------------------------------------------------|
| GOSEC\_RAW\_OUT\_FILE\_PATH  | string | yes      | -          | The path where to find the gosec report                 |

## Test data

The `gosec.sarif` file used in tests was generated with the following steps:

* Cloning:

```shell
git clone https://github.com/TheHackerDev/damn-vulnerable-golang
```

* Running gosec

```shell
docker run \
  --platform linux/amd64 \
  -v ./damn-vulnerable-golang:/go/damn-vulnerable-golang \
  -it securego/gosec:2.15.0 \
    -fmt=sarif \
    -no-fail \
    -out=./damn-vulnerable-golang/gosec.sarif \
      damn-vulnerable-golang
```
