# Developing a component

Smithy offers an SDK to allow users to easily develop custom components for the platform and share
them with other users. As of the time of this writing, the SDK supports the following component
types:

1. targets
2. scanners
3. filters
4. enrichers
5. reporters

## Component Types

Targets are components that fetch artifacts from an API, source code host, etc. and these artifacts
are the ones that will be scanned by the next layer of components

Scanners are the components that use some binary, API or custom logic to discover vulnerabilities
in an artifact and will then parse the results into Vulnerability Finding objects of the OCSF
standard

Filters get a list of all the Vulnerability Findings discovered within the context of the workflow
execution and hide some of them from the rest of the components

Enrichers add more context and information to the Vulnerability Findings

Reporters report the Vulnerability Findings to some external system, such as a database, a
messenger, etc.

## Component Execution

Components execute in a specific order that can't be modified and is the following:

1. Targets
2. Scanners
3. Filters
4. Enrichers
5. Reporters

Components can be added in any order in a workflow specification, however they will always be
ordered to match the order specified above.
The filters are the only components that are optional, for each one of the other types of
components you need to have at least on in the workflow specification in order for it to be
considered valid.

## Component Types and SDK

The SDK models how each type of components interacts with the Vulnerability Findings.

Targets don't have any interaction, they just fetch the artifacts so that they can become
accessible by the scanners.

Scanners produce Vulnerability Findings and the SDK ensures that they will be stored in the
database. They don't modify any existing vulnerabilities.

Filters don't create new Vulnerability Findings, they can hide them but they can't delete them.
A Vulnerability Finding once produced by a scanner, will remain in the database, it can be hidden,
annotated or contextualised but not deleted.

Enrichers enrich Vulnerability Findings that have not been hidden by the filters. They operate only
on data that have been produced in the context of the current workflow execution, they don't have
access to historical data.

Reporters get a list of enriched Vulnerability Findings, they can't modify them in any way but they
can report them to an external system for further processing.

## Building a component's images

If you want to build a component's images and share the manifest with other users you can do
so using the following commands:

```bash
smithyctl --debug-enabled component build --sdk-version v1.0.0 \
                                          --tag v0.0.9 \
                                          --registry-url <some-registry> \
                                          components/scanners/<your-component-name>/component.yaml

smithyctl --debug-enabled component package --sdk-version v1.0.0 \
                                            --version v0.0.9 \
                                            --registry-url <some-registry> \
                                            components/scanners/<your-component-name>/component.yaml
```

The first command will build any images required by the component and the second will resolve
all the image references in the component and will then push the rendered component manifest to the
registry.

A component's image must be an abstract reference that matches the path of the component in the
repository. For example, the scanner named `sql-injection` whose manifest resides in the path
`components/scanners/sql-injection/component.yaml` could have the following image references:

1. ubuntu:24.04
2. components/scanners/sql-injection
3. components/scanners/sql-injection/helper

The first image is a third-party image, it will be resolved to
`index.docker.io/library/ubuntu:24.04` and will be fetched before the component starts its
execution. The second and third images are component images, meaning that `smithyctl` is able to
build them for you in a consistent way. At the moment, the Smithy SDK is only available in Go and
hence we have a standard way of building our images using a base Dockerfile and changing the
context and a couple of build arguments.

Since each component image is practically a path in the repo, we expect all images to be Go
modules located in the respective path. The image build will use the path as the context path. You
can set one or more tags and the registry host to be added to the resulting image reference. So,
the command:

```bash
smithyctl --debug-enabled component build --sdk-version v1.0.0 \
                                          --tag v0.0.9 \
                                          --tag latest \
                                          --tag current-staging \
                                          --registry-url some-registry.com \
                                          --namespace smithy \
                                          --base-component-dockerfile components/Dockerfile \
                                          components/scanners/sql-injection/component.yaml
```

will result in 2 images being built with the following tags:

1. some-registry.com/smithy/components/scanners/sql-injection:v0.0.9
2. some-registry.com/smithy/components/scanners/sql-injection:latest
3. some-registry.com/smithy/components/scanners/sql-injection:current-staging
4. some-registry.com/smithy/components/scanners/sql-injection/helper:v0.0.9
5. some-registry.com/smithy/components/scanners/sql-injection/helper:latest
6. some-registry.com/smithy/components/scanners/sql-injection/helper:current-staging

The Docker command that would yield the same result would like this:

```bash
docker build -t some-registry.com/smithy/components/scanners/sql-inection:v0.0.9 -f components/Dockerfile --build-arg ... components/scanners/sql-injection/
docker build -t some-registry.com/smithy/components/scanners/sql-inection:v0.0.9 -f components/Dockerfile --build-arg ... components/scanners/sql-injection/helper/
```

You can get a report of what would the `smithyctl component build` resolve and built by using the
`--dry-run` flag to get a machine readable report of all the actions in the stdout. An example for
the current version of the gosec component is the following:

```bash
./bin/smithyctl/cmd/linux/amd64/smithyctl component build --dry-run \
                                                          --tag v0.0.9 \
                                                          --tag latest \
                                                          --tag current-staging \
                                                          --sdk-version v1.0.0 \
                                                          new-components/scanners/gosec/component.yaml 
...
custom_images:
    - tags:
        - ghcr.io/smithy-security/images/new-components/scanners/gosec:v0.0.9
        - ghcr.io/smithy-security/images/new-components/scanners/gosec:latest
        - ghcr.io/smithy-security/images/new-components/scanners/gosec:current-staging
      labels:
        org.opencontainers.image.source: https://github.com/smithy-security/smithy
      build_args:
        COMPONENT_PATH: new-components/scanners/gosec
        SDK_VERSION: v1.0.0
      context_path: new-components/scanners/gosec
      dockerfile: new-components/Dockerfile
      component_path: new-components/scanners/gosec
      platform: linux/amd64
external_images:
    docker.io/securego/gosec:2.15.0: {}
```

A component manifest package can be built independently of an image. The packaging command renders
all component images to have the full image URLs for all the steps. Contrary to the image building
command, the packaging command doesn't allow for component images to have multiple tags, because
only one can be rendered in the component.

Suppose that our `sql-injection` component has the following manifest:

```yaml
name: sql-injection
type: scanner
steps:
  - name: scanner
    image: ubuntu:24.04
    executable: /bin/app
  - name: parser
    image: components/scanners/sql-injection
    executable: /bin/app
  - name: parser
    image: components/scanners/sql-injection/helper
    executable: /bin/app
```

The command

```bash
./bin/smithyctl/cmd/linux/amd64/smithyctl component package --version v0.0.9 \
                                                            --sdk-version v1.0.0 \
                                                            --registry-url some-registry.com \
                                                            --namespace smithy \
                                                            new-components/scanners/sql-injection/component.yaml 
```

will render it into the following manifest before packaging into OCI and pushing it:

```yaml
name: sql-injection
type: scanner
steps:
  - name: scanner
    image: index.docker.io/library/ubuntu:24.04
    executable: /bin/app
  - name: parser
    image: some-registry.com/smithy/components/scanners/sql-injection:v0.0.9
    executable: /bin/app
  - name: parser
    image: some-registry.com/smithy/components/scanners/sql-injection/helper:v0.0.9
    executable: /bin/app
```

If you wish to apply some rendering on the packaged manifest with go templates for example, you
could run the following command:

```bash
./bin/smithyctl/cmd/linux/amd64/smithyctl component package --version '{{ some-version.parameter }}' \
                                                            --sdk-version v1.0.0 \
                                                            --registry-url some-registry.com \
                                                            --namespace smithy \
                                                            new-components/scanners/sql-injection/component.yaml 
```

and you will get the following result:

```yaml
name: sql-injection
type: scanner
steps:
  - name: scanner
    image: index.docker.io/library/ubuntu:24.04
    executable: /bin/app
  - name: parser
    image: some-registry.com/smithy/components/scanners/sql-injection:{{ some-version.parameter }}
    executable: /bin/app
  - name: parser
    image: some-registry.com/smithy/components/scanners/sql-injection/helper:{{ some-version.parameter }}
    executable: /bin/app
```
