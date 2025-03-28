# Run

Run allows to run workflows specified in `workflow.yaml` files.

Run will:

* look for your [workflow.yaml](./SPEC.md) spec and validate it
* fetch local and remote `component.yaml` specifications
* apply overrides, if specified
* execute all the components in the following order based on component type:
  * `target`
  * `scanner`
  * `enricher`
  * `filter`
  * `reporter`

```shell
smithyctl workflow run
```

## Flags

| Flag                        | Description                                                        | Default                                |
|-----------------------------|--------------------------------------------------------------------|----------------------------------------|
| `spec-path`                 | is the path to the component's `workflow.yaml` file.               | -                                      |
| `overrides-path`            | is the path to workflow overrides.                                 | -                                      |
| `registry-url`              | the base URL of the OCI registry                                   | `localhost:5000`                       |
| `registry-auth-enabled`     | enables authentication to push artifact to an OCI registry.        | `false`                                |
| `registry-auth-username`    | the username for authenticating to the OCI registry.               | `""`                                   |
| `registry-auth-password`    | the password for authenticating to the OCI registry.               | `""`                                   |
| `registry-base-repository`  | where to upload packaged manifests to                              | `smithy-security/manifests/components` |
| `clean-run`                 | if 'true' the findings db will be emptied out                      | `false`                                |
| `build-component-images`    | if 'true' components' images will be automatically built on run    | `true`                                 |
| `image-registry`            | registry to use for the images | local                             |                                        |
| `image-namespace`           | namespace that will be added to all the images built by the system | smithy-security/smithy                 |
| `base-component-dockerfile` | base Dockerfile to use to build all the images                     | components/Dockerfile                  |

## Example

### With remote packages - ghcr.io

```shell
smithyctl \
  workflow \
    run \
      --spec-path=path/to/workflow.yaml \
      --registry-auth-enabled=true \
      --registry-auth-username=$USERNAME \ 
      --registry-auth-password=$PASSWORD \
      --registry-url=ghcr.io
```

### With local components - docker or local references

```shell
smithyctl \
  workflow \
    run \
      --spec-path=path/to/workflow.yaml \
      --build-component-images=true
```
