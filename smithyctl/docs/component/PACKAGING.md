# Packaging

Packaging allows to distribute a component and make it available for execution.

Packaging will:

* look for your [component.yaml](./SPEC.md) spec and validate it
* package its configuration in an OCI blob and manifest
* upload the manifest into the specified OCI registry

```shell
smithyctl component package
```

## Flags

| Flag                     | Description                                                 | Default                            |
|--------------------------|-------------------------------------------------------------|------------------------------------|
| `spec-path`              | is the path to the component's `component.yaml` file.       | -                                  |
| `registry-url`           | the base URL of the OCI registry                            | `localhost:5000`                   |
| `registry-auth-enabled`  | enables authentication to push artifact to an OCI registry. | `false`                            |
| `registry-auth-username` | the username for authenticating to the OCI registry.        | `""`                               |
| `registry-auth-password` | the password for authenticating to the OCI registry.        | `""`                               |
| `namespace`              | repository context path                                     | `smithy-security/smithy/manifests` |
| `sdk-version`            | specifies the sdk version used to package the component.    | `latest`                           |
| `version`                | is the version used to package the component.               | `latest`                           |

## Example

### Remote registry - ghcr.io

```shell
smithyctl \
  component \
    package \
        --registry-auth-enabled=true \
        --registry-auth-username=${USER} \
        --registry-auth-password=${PASSWORD} \
        --registry-url=ghcr.io \
        --sdk-version=v1.0.0 \
        --version=v3.2.1 \
        new-components/scanners/bandit/component.yaml
```

### Local registry - docker

Run a docker registry:

```shell
docker run --publish "127.0.0.1:5000:5000" registry:2
```

In another terminal, run:

```shell
smithyctl \
  component \
    package \
        --registry-url=127.0.0.1:5000 \
        --sdk-version=v1.0.0 \
        --version=v3.2.1 \
        new-components/scanners/bandit/component.yaml
```
