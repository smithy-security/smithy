# discord

This component implements a [reporter](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go)
that reports OCSF findings generated from running a workflow to Discord.

## Environment variables

The component uses environment variables for configuration.

It requires the component
environment variables defined [here](https://github.com/smithy-security/smithy/blob/main/sdk/README.md#component)
as well as the ones defined in the [component.yaml](./component.yaml).

## Manual testing

Check out the instructions [here](./test/README.md).

## Configuration

To operate, the component needs a bot configured with the following permissions
for scopes `bot`:

* Send Messages - public/private
* Create Threads - public/private

You should then set up your both on your server and invite it to
your preferred channel.

Safely store the auth token and use it as a secret for `DISCORD_AUTH_TOKEN`.

After enabling development settings on your discord, you can then get the
`DISCORD_CHANNEL_ID` by browsing its settings.
