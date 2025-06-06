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
smithyctl workflow run [FLAGS] SPEC_PATH
```

## Flags

| Flag                        | Description                                                        | Default                                |
|-----------------------------|--------------------------------------------------------------------|----------------------------------------|
| `overrides`                 | is the path to workflow overrides.                                 | -                                      |
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

SPEC\_PATH: the path to the workflow YAML listing all the components that should be used

## Example

### With remote packages - ghcr.io

```shell
smithyctl \
  workflow \
    run \
      --registry-auth-enabled=true \
      --registry-auth-username=$USERNAME \ 
      --registry-auth-password=$PASSWORD \
      --registry-url=ghcr.io \
      path/to/workflow.yaml
```

### With local components - docker or local references

```shell
smithyctl \
  workflow \
    run \
      --build-component-images=true \
      path/to/workflow.yaml
```
