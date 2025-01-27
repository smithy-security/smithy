# Smithyctl

Smithyctl is the CLI used to develop new components, run them in workflows and distributing them.

## Installation

```shell
go install github.com/smithy-security/smithyctl@latest
```

Verify installation by running:

```shell
smithyctl version
```

## Commands

| Command     | Description                                                 | Status                |
|-------------|-------------------------------------------------------------|-----------------------|
| `help`      | will output how to use `smithyctl`                          | Implemented           |
| `version`   | will output the version of the installed `smithyctl` binary | Not implemented yet   |
| `component` | allows to develop, run and distribute components            | Not fully implemented |
| `workflow`  | allows to develop and run workflows                         | Not implemented yet   |

Flags:

| Flag          | Description                                                                 | Default   |
|---------------|-----------------------------------------------------------------------------|-----------|
| `debug-enabled` | enabled debug logs.                                                         | `false`     |
| `debug-level`   | sets the log level. Possible values `debug`, `info`, `warning` and `error`. | `debug`   |

### Component

#### Packaging

Packaging allows to distribute a component and make it available for execution.

Packaging will:

* look for your `smithy-component.yaml` spec and validate it
* package its configuration in an OCI blob and manifest
* upload the manifest into the specified OCI registry

```shell
smithyctl component package
```

##### Flags

| Flag                   | Description                                                  | Default       |
|------------------------|--------------------------------------------------------------|---------------|
| `spec-path`              | is the path to the component's `smithy-component.yaml` file. | `.`             |
| `registry-url`           | the base URL of the OCI registry                             | `localhost:5000` |
| `registry-auth-enabled`  | enables authentication to push artifact to an OCI registry.  | `false`         |
| `registry-auth-username` | the username for authenticating to the OCI registry.         | `""`            |
| `registry-auth-password` | the password for authenticating to the OCI registry.         | `""`            |
| `registry-base-repository` | where to upload packaged manifests to                        | `smithy-security/manifests/components`             |
| `sdk-version`            | specifies the sdk version used to package the component.     | `latest`      |
| `version`                | is the version used to package the component.                | `latest`      |

##### Example

```shell
smithyctl \
  --debug-enabled=true \
  --debug-level=debug \
  component \
    package \
        --registry-auth-enabled=true \
        --registry-auth-username=smithy \
        --registry-auth-password=XXX \
        --registry-url=ghcr.io \
        --sdk-version=v1.0.0
        --spec-path=new-components/scanners/bandit
        --version=v3.2.1
```
