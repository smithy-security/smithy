# linear

This component implements a [reporter](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go)
that reports OCSF findings generated from running a workflow to Discord.

## Environment variables

The component uses environment variables for configuration.

It requires the component
environment variables defined [here](https://github.com/smithy-security/smithy/blob/main/sdk/README.md#component)
as well as the ones defined in the [component.yaml](./component.yaml).

## Manual testing

Check out the instructions [here](./test/manual/README.md).

## Configuration

To operate this component, you need to:

* supply a valid [Linear API Key](https://linear.app/docs/api-and-webhooks): used as `LINEAR_API_KEY` env var.
* supply a valid Team ID: run the app in [get-teams](./test/get-teams) to find yours. This is used as `LINEAR_TEAM_ID` env var.
* supply your preferred issue labels as comma separated string, for example: `"vulnerability,mylabel1".`. This is case-sensitive, so be careful. This is used as `LINEAR_LABEL_NAMES` env var.
