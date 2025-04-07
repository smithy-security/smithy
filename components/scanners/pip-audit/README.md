# pip-audit

This component implements a [scanner](https://github.com/smithy-security/smithy/blob/main/sdk/component/component.go)
that parses json reports output by [bandit](https://github.com/securego/gosec) into [ocsf](https://github.com/ocsf) format.

## Environment variables

The component uses environment variables for configuration.

It requires the component
environment variables defined [here](https://github.com/smithy-security/smithy/blob/main/sdk/README.md#component) as well
as the following:

| Environment Variable     | Type   | Required | Default    | Description                                             |
|--------------------------|--------|----------|------------|---------------------------------------------------------|
| PIP\_AUDIT\_RAW\_OUT\_FILE\_PATH  | string | yes      | -          | The path where to find the gosec report                 |
| PIP\_AUDIT\_TARGET\_TYPE         | string | false    | repository | The type of target that was used to generate the report |
| REQUIREMENTS\_FILE\_NAME         | string | false    | requirements.txt | The name of the dependencies file                       |
| PYPROJECT\_FILE\_NAME         | string | false    | pyproject.toml | The name of the PyProject file                          |

## Test data

The `results.json` file used in tests was generated with the following steps:

* Cloning:

```shell
git clone https://github.com/anxolerd/dvpwa
```

* Running pip-audit

```shell
todo
```
