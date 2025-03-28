# trufflehog

This component implements a
[scanner](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go)
that parses [trufflehog](https://github.com/trufflesecurity/trufflehog)
filesystem reports output
into [ocsf](https://github.com/ocsf) format.

## Environment variables

The component uses environment variables for configuration.

It requires the component
environment variables defined [here](https://github.com/smithy-security/smithy/blob/main/sdk/README.md#component)
as well
as the following:

| Environment Variable     | Type   | Required | Default    | Description                                             |
|--------------------------|--------|----------|------------|---------------------------------------------------------|
| TRUFFLEHOG\_RAW\_OUT\_FILE\_PATH  | string | yes      | -          | The path where to find the trufflehog report                 |
| TRUFFLEHOG\_TARGET\_TYPE         | string | false    | repository | The type of target that was used to generate the report |

## How to run

Execute:

```shell
docker-compose up --build --force-recreate --remove-orphans
```

Then shutdown with:

```shell
docker-compose down --rmi all
```

## Test data

The `trufflehog.json` file used in tests was generated with the following steps:

* Cloning:

```shell
git clone https://github.com/smithy-security/e2e-monorepo
```

* Running trufflehog

```shell
docker run \
    --rm -it -v "$PWD:/pwd" \
     trufflesecurity/trufflehog:latest \
     filesystem --json \
     --no-fail \
     --no-update \
     --log-level=-1 \
     --directory="/pwd"
```
