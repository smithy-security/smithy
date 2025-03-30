# slack

This component implements a [reporter](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go)
that sends a summary of results to slack.

## Environment variables

The component uses environment variables for configuration.

It requires the component
environment variables defined [here](https://github.com/smithy-security/smithy/blob/main/sdk/README.md#component).
as well as the following:

| Environment Variable       | Type   | Required | Default | Description                                                             |
|----------------------------|--------|----------|---------|-------------------------------------------------------------------------|
| SLACK\_WEBHOOK     | string | yes      | -       | The slack webhook to POST results to|
