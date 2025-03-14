# Build

Packaging allows the components' images to be built and pushed to a container registry.

```shell
smithyctl component build
```

## Flags

| Flag                   | Description                                                                     | Default                   |
|------------------------|---------------------------------------------------------------------------------|---------------------------|
| `registry`              | registry to use for the images                                                  | ghcr.io                   |
| `namespace`              | namespace that will be added to all the images built by the system              | smithy-security/smithy    |
| `base-component-dockerfile`              | base Dockerfile to use to build all the images                                  | new-components/Dockerfile |
| `registry-auth-username`              | username to authenticate with for the image registry                            | -                         |
| `registry-auth-password`              | password to authenticate with for the image registry                            | -                         |
| `label`              | labels to be added to the image                                                 | -                         |
| `push`              | push images once they are built                                                 | false                     |
| `platform`              | build an image for a platform other than one where the Docker server is running |                           |
| `tag`              | tags to use for images, can be multiple                                         | latest                    |

## Example

### Local registry - docker

```shell
smithyctl \
  component \
  build \
  path/to/component.yaml
```
