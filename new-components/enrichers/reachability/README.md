# custom-annotation

This component implements an [enricher](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go)
This enricher performs reachability analysis using [atom](https://github.com/AppThreat/atom).

## Environment variables

The component uses environment variables for configuration.

It requires the component
environment variables defined [here](https://github.com/smithy-security/smithy/blob/main/sdk/README.md#component) as well as the following:

| Environment Variable       | Type   | Required | Default | Description                                                             |
|----------------------------|--------|----------|---------|-------------------------------------------------------------------------|
| ATOM\_FILE\_PATH    | string | yes      | -       | Path to the file where atom has produced reachable slices.                     |

## How to run

Execute:

```shell
docker-compose up --build --force-recreate --remove-orphans
```

Then shutdown with:

```shell
docker-compose down --rmi all
```
