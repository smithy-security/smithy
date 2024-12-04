# json-logger

This component implements a [reporter](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go)
that prints vulnerability findings as json.

## Environment variables

The component uses environment variables for configuration.

It requires the component
environment variables defined [here](https://github.com/smithy-security/smithy/blob/main/sdk/README.md#component).

## How to run

Execute:

```shell
docker-compose up --build --force-recreate --remove-orphans
```

Then shutdown with:

```shell
docker-compose down --rmi all
```
