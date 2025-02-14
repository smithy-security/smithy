# Component Specification

A component specification allows to configure a component.

## component.yaml

An example `component.yaml` looks like:

```yaml
name: "git-clone"
description: "Clones a repository"
type: "target"
parameters:
  - name: "repo_url"
    type: "string"
    value: "https://github.com/0c34/govwa.git"
  - name: "reference"
    type: "string"
    value: "master"
steps:
  - name: "clone-repo"
    image: "localhost:5000/components/targets/git-clone:latest"
    env_vars:
      LOG_LEVEL: "debug"
      GIT_CLONE_REPO_URL: "{{ .parameters.repo_url }}"
      GIT_CLONE_REFERENCE: "{{ .parameters.reference }}"
```

Here we specify things like which environment variables and which run time overridable parameters
are supported by the component.

| Field         | Description                                                                                      | Required            |
|---------------|--------------------------------------------------------------------------------------------------|---------------------|
| `name`        | is the name of the component                                                                     | `yes`               |
| `description` | is the description of the component                                                              | `yes`               |
| `type`        | specifies the component type. It can be: `target`, `scanner`, `enricher`, `filter` or `reporter` | `yes`               |
| `parameters`  | specifies the run time overridable parameters of the component                                   | `no`                |
| `steps`       | an array of component steps to be executed                                                       | `yes`, at least one |

### Parameters

Parameters allow to define overridable settings at run time.

They can be referenced with the [go template](https://pkg.go.dev/text/template)'s syntax, and they must start with
`.parameters`, for example `"{{ .parameters.repo_url }}"`. You can read more about overrides [here](../workflow/SPEC.md).

| Field   | Description                                                                                  | Required |
|---------|----------------------------------------------------------------------------------------------|----------|
| `name`  | is the name of the parameter                                                                 | `yes`    |
| `type`  | specifies the parameter type. It can be: `string`, `const:string` or `list:string`           | `yes`    |
| `value` | specifies the default value of the parameter. It can be: a `string` or an array of `string`s | `yes`    |

### Steps

Steps allow to define what the component has to execute. At least one step has to be specified.

| Field      | Description                                        | Required |
|------------|----------------------------------------------------|----------|
| `name`     | is the name of the step                            | `yes`    |
| `image`    | is the image of the step to be executed            | `yes`    |
| `env_vars` | defines optional environment variables of the step | `no`     |
