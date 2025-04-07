# DefectDojo

This component implements a [reporter](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go)
that sends vulnerability findings to a remote defectdojo instance.

## Environment variables

The component uses environment variables for configuration.

It requires the component
environment variables defined [here](https://github.com/smithy-security/smithy/blob/main/sdk/README.md#component).
It also requires the following environment variables

| Environment Variable  | Type   | Required | Default | Description                                                          |
|-----------------------|--------|----------|---------|----------------------------------------------------------------------|
| DOJO\_USER | string | yes | -       | The username of the DefectDojo API Key owner |
| DOJO\_API\_KEY | string | yes | -       | An API key for defectdojo |
| DOJO\_API\_URL | string | yes | -       | The url for the remote defectdojo api, it needs to end in '/api/v2/' |
| DOJO\_PRODUCT\_ID | string | yes | -       | The ID of the product in DefectDojo for which engagements and tests will be created |
