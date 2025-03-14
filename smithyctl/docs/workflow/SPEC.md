# Workflow Specification

A workflow specification allows to configure a workflow.

## workflow.yaml

An example `workflow.yaml` looks like:

```yaml
description: GoSec based workflow
name: gosec
components:
  - component: file://new-components/targets/git-clone/component.yaml
  - component: file://new-components/scanners/gosec/component.yaml
  - component: file://new-components/enrichers/custom-annotation/component.yaml
  - component: file://new-components/reporters/json-logger/component.yaml
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
gosec-parser:
  - name: "repo_name"
    type: "string"
    value: "govwa"
```

The root entries specify the component name, while the entries are parameters.
