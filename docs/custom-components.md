# Building Custom Components

In this document we assume that you have KinD up and running.

If that's not the case, see the
[Getting Started](./getting-started.md) guide.

If instead you are using another setup for your local Kubernetes
environment or docker registry, you might have to tweak
the address for your local docker registry.

## Deploying a custom version of Smithy components

The first step is to build all the containers and push them to a registry
that your cluster has access to. We use `make` to package our containers. For
each component our Make will automatically generate a phony target with the
path `components/{component type}/{component name}/docker`. We have a top-level
target that creates all the component containers along with a couple of extra
containers our system uses, such as smithyctl.

The following examples are using the local container registry used by the KiND
cluster, but make sure that you replace the URL with the registry URL that you
are using, if you are using something else:

```bash
make publish-component-containers CONTAINER_REPO=localhost:5000/smithy-security/smithy
```

*\*Notice that the repo we are using is slightly different from the
one we pushed the images in the previous step. That's because with local
registries the registry is exposed on a port in localhost, however inside the
KiND cluster, that's not the case. Instead, the registry's host is
`kind-registry:5000`. This is also going to be important later when we will
deploy the pipelines and their image repositories will also have to be set to
this value.*

*\*\*Make sure that you use the smithyctl image that you pushed in the
repository.*

### Using a different base image for your images

If you need your images to have a different base image then you can pass the
`BASE_IMAGE` variable to the `components` or `publish-component-containers` to
change it to whatever you need. The targets build the binaries and place them in
the `bin` directory and then other targets package them into containers with
`scratch` as the base image.

There are some components that require extra components or special treatment and
these components have their own Makefiles. In those cases you can place a
`.custom_image` file in the directory with the base image you wish to use and
that will be picked up by the Makefile and build the container.

### Building binaries and images for non linux/amd64 architecture

*\*Useful for Apple Silicon chips users.*

##### Containers

If you need your images to be built for non linux/amd64 architecture,
you can supply the `GOOS` and `GOARCH` flags for customisation of containers.

This can be passed to the make commands used to build images, for example:

```bash
make GOOS=linux GOARCH=arm64 components
```

or:

```bash
make GOOS=linux GOARCH=arm64 publish-containers
```

By default, when `GOOS` and `GOARCH` are not supplied,
`linux` and `amd64` are used.

##### Binaries

`GOOS` and `GOARCH` can be supplied for customisation of the go binaries.

These can be passed to the make commands used to build binaries, for example:

```bash
make GOOS=linux GOARCH=arm64 component-binaries
```

By default `linux` and `amd64` are used.

\**For Apple Silicon chips, you might want to use
`GOOS=darwin` and `GOARCH=arm64` when building binaries
locally for development.*

### Deploying your custom Smithy components Helm package

You can package your components into a Helm package by running the following
command:

```bash
export CUSTOM_SMITHY_VERSION=$(make print-SMITHY_VERSION)
export CUSTOM_HELM_COMPONENT_PACKAGE_NAME=my-custom-component
make cmd/smithyctl/bin
bin/cmd/smithyctl components package \
  --version ${CUSTOM_SMITHY_VERSION} \
  --chart-version ${CUSTOM_SMITHY_VERSION} \
  --name ${CUSTOM_HELM_COMPONENT_PACKAGE_NAME} \
  ./components
helm upgrade ${CUSTOM_HELM_COMPONENT_PACKAGE_NAME} ./${CUSTOM_HELM_COMPONENT_PACKAGE_NAME}-${CUSTOM_SMITHY_VERSION}.tgz \
  --install \
  --namespace smithy \
  --values deploy/smithy/values/dev.yaml
```

Notice that you have to specify the name of a custom component via `CUSTOM_HELM_COMPONENT_PACKAGE_NAME`.

If your custom components are local, you need to override the component registry
you can do so with the following slightly modified helm command

```bash
helm upgrade ${CUSTOM_HELM_COMPONENT_PACKAGE_NAME} ./${CUSTOM_HELM_COMPONENT_PACKAGE_NAME}-${CUSTOM_SMITHY_VERSION}.tgz \
  --install \
  --namespace smithy \
  --set image.registry=kind-registry:5000/smithy-security/smithy \
  --values deploy/smithy/values/dev.yaml
```

After changes to your components you need to redeploy, you can do so as such:

```bash
export CUSTOM_SMITHY_VERSION=$(make print-SMITHY_VERSION)
make publish-component-containers CONTAINER_REPO=localhost:5000/smithy-security/smithy
bin/cmd/smithyctl components package \
  --version ${CUSTOM_SMITHY_VERSION} \
  --chart-version ${CUSTOM_SMITHY_VERSION} \
  --name ${CUSTOM_HELM_COMPONENT_PACKAGE_NAME} \
  ./components 
helm upgrade ${CUSTOM_HELM_COMPONENT_PACKAGE_NAME} \
  ./${CUSTOM_HELM_COMPONENT_PACKAGE_NAME}-${CUSTOM_SMITHY_VERSION}.tgz \
  --install \
  --namespace smithy \
  --set image.registry=kind-registry:5000/smithy-security/smithy \
  --values deploy/smithy/values/dev.yaml
```
