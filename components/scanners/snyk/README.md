# Snyk

This component implements a [scanner](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go)
that parses [sarif](https://sarifweb.azurewebsites.net/) reports output
by [snyk-cli](https://github.com/snyk/cli) into [ocsf](https://github.com/ocsf) format.

## Parser Environment variables

The component uses environment variables for configuration.

It requires the component
environment variables defined [here](https://github.com/smithy-security/smithy/blob/main/sdk/README.md#component) as well
as the following:

| Environment Variable | Type   | Required | Default    | Description                                   |
|----------------------|--------|----------|------------|-----------------------------------------------|
| RAW\_OUT\_FILE\_PATH | string | yes      | -          | The path where to find the snyk sarif report  |
| HTTP\_PROXY          | string | no       | -          | HTTP proxy to use for connecting to Snyk[^1]  |
| HTTPS\_PROXY         | string | no       | -          | HTTPS proxy to use for connecting to Snyk[^1] |
| SNYK\_TOKEN          | string | yes      | -          | Snyk API token[^2]                            |

[^1]: https://support.snyk.io/s/article/How-can-I-use-Snyk-behind-a-proxy

[^2]: https://docs.snyk.io/snyk-cli/authenticate-to-use-the-cli#how-to-authenticate-to-use-the-cli-in-ci-cd-pipelines
