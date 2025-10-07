# Elasticsearch

This component implements a [reporter](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go)
that sends vulnerabilities to elasticsearch.

It supports authenticating to elasticsearch using an API key.
The API key requires reading cluster's information in order for the  component to
validate connectivity and write to any indexes you plan on using this component
with.

## Environment variables

The component uses environment variables for configuration.

It requires the component
environment variables defined [here](https://github.com/smithy-security/smithy/blob/main/sdk/README.md#component).
as well as the following:

| Environment Variable       | Type   | Required | Default | Description                                                             |
|----------------------------|--------|----------|---------|-------------------------------------------------------------------------|
| ELASTICSEARCH\_URL     | string | yes      | -       | The remote instance to connect to.                                 |
| ELASTICSEARCH\_INDEX   | string | yes       | -      | The index to write results to |
| ELASTICSEARCH\_API\_KEY   | string | yes       | -      | The api key to use to write results. |
