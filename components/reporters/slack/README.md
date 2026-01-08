# slack

This component implements a [reporter](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go)
that sends a summary of results to slack and optionally creates detailed vulnerability threads.

## Environment variables

The component uses environment variables for configuration.

It requires the component
environment variables defined [here](https://github.com/smithy-security/smithy/blob/main/sdk/README.md#component).
as well as the following:

| Environment Variable       | Type   | Required | Default | Description                                                             |
|----------------------------|--------|----------|---------|-------------------------------------------------------------------------|
| SLACK\_TOKEN       | string | no       | -       | The slack bot token (required for thread creation mode)|
| SLACK\_CHANNEL     | string | no       | -       | The slack channel ID (required for thread creation mode)|
| SLACK\_DEBUG       | bool   | no       | false   | Whether to enable debug logging for the slack client|

## Operation

* Uses `SLACK_TOKEN` and `SLACK_CHANNEL` for Web API access
* Creates threads with detailed vulnerability information
* Requires bot setup with appropriate permissions -- read on for details
* Sends both summary and detailed findings

## Bot Setup for Thread Creation

To use thread creation mode, you need to:

1. Create a Slack app in your workspace
2. Add the following bot token scopes:
   * `chat:write` - Send messages to channels
   * `channels:read` - Read channel information
3. Install the app to your workspace
4. Invite the bot to the target channel
5. Use the bot token as `SLACK_TOKEN`
6. Use the channel ID as `SLACK_CHANNEL`

## Example Configuration

```yaml
parameters:
  - name: "slack_token"
    type: "string"
    value: "xoxb-your-bot-token"
  - name: "slack_channel"
    type: "string"
    value: "C1234567890"
  - name: "create_threads"
    type: "bool"
    value: "true"
```

## FAQ

* Why do I need a bot token?
  * The bot token is required for thread creation and sending messages to channels. It allows the app to interact with Slack's Web API.
* Why do I need a channel ID?
  * The channel ID is required to specify which channel the bot will send messages to. It ensures that the messages are delivered to the correct location.
  * You can find the channel ID by right-clicking on the channel name in Slack and selecting "Copy Link". The ID is the part after `/archives/` in the URL.
  * If you are using the Slack APP, the channel ID is located at the very bottom in the channel details pane.
* Help, I created a token but it doesn't work!
  * Make sure you have invited the bot to the channel you want to post in. The bot needs to be a member of the channel to send messages.
  * Ensure that the bot has the necessary permissions (scopes) to send messages and create threads.
  * Check that you are using the correct token and channel ID in your configuration.
  * If you didn't add the correct permissions when creating the bot then you need to recreate the bot token and re-invite the bot to the channel. Slack docs do not mention this at the time of writing.
