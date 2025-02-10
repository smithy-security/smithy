# Workflow Specification

A workflow specification allows to configure a workflow.

## workflow.yaml

An example `workflow.yaml` looks like:

```yaml
description: "Example pipeline"
name: "example-pipeline"
components:
  - component: "ghcr.io/smithy-security/manifests/components/target/git-clone:v1.0.0"
  - component: "ghcr.io/smithy-security/manifests/components/scanner/gosec-parser:v1.0.0"
  - component: "file://new-components/enrichers/custom-annotation/component.yaml"
  - component: "ghcr.io/smithy-security/manifests/components/reporter/json-logger:v1.0.0"
```

Component references can be:

* `local`: absolute path to a `component.yaml` with `file://` prefix.
* `remote`: referring to a packaged component pushed in an OCI registry.

## overrides.yaml

An overrides file defines optional parameter overrides for each component at run time.

An example `overrides.yaml` file looks like follows:

```yaml
git-clone:
  - name: "repo_url"
    type: "string"
    value: "https://github.com/0c34/govwa.git"
  - name: "repo_name"
    type: "string"
    value: "govwa"
gosec-parser:
  - name: "repo_name"
    type: "string"
    value: "govwa"
```

The root entries specify the component name, while the entries are parameters.
