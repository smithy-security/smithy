# Image-Get

This component implements a [target](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go)
that logs in to the target registry with the username and the password provided, downloads an image and saves it locally for scanning.
The name of the downloaded image is always `image.tar.gz` and the location is the {{ sourceCodeWorkspace }}.

## Environment variables

The component uses environment variables for configuration.

| Environment Variable     | Type   | Required | Default    | Description                                             |
|--------------------------|--------|----------|------------|---------------------------------------------------------|
| TOKEN  | string | yes      | -          | The token to use to login, either a password or an api key |
| USERNAME        | string | false    | - | The username to use to login |
| IMAGE\_REF | string | true    | - | The image reference to download |
