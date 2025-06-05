# custom-annotation

This component implements an [enricher](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go)
that adds a custom json annotation to the fetched vulnerability findings
associated with the workflow.

## Environment variables

The component uses environment variables for configuration.

It requires the component
environment variables defined [here](https://github.com/smithy-security/smithy/blob/main/sdk/README.md#component)
as well as the following:

| Environment Variable       | Type   | Required | Default | Description                                                             |
|----------------------------|--------|----------|---------|-------------------------------------------------------------------------|
| CUSTOM\_ANNOTATION\_NAME     | string | yes      | -       | The name of the annotation to be added.                                 |
| CUSTOM\_ANNOTATION\_VALUES   | string | no       | {}      | Json annotations to be added as annotation. For example '{"foo":"bar"}' |
