# How Smithy works

## Architecture

Smithy is using Tekton as a scheduling and execution layer on top of Kubernetes.
Each component is
comprised of a binary that is wrapped in a container image and a Tekton Task
object, which is a Tekton CRD describing how the container will be used execute
some quantum of processing.

## Components

Smithy has 3 types of components:

1. Producers: they run a binary with eg. some source code as input and produce
   some results
2. Enrichers: they use the output of one or more producers and enrich it with
   metadata
3. Consumers: they consume results from other jobs and redirect it to some sink,
   such as a database

Each Task must be labelled with the type of component that is packaged in the
image it references.
The label must have the name `v1.smithy.smithy-security.com/component` and the value
must be one of:

1. consumer
2. producer
3. enricher

## Kustomize

We use kustomize as a build system for the Pipelines. A Pipeline is a Tekton CRD
describing how a number of Tasks are connected to each other to produce some
result and store it in a database or producer a ticket (or both).
Each component must define a Tekton Task object which is used as input to our
`smithyctl`
to produce a `kustomization.yaml`. This kustomization describes how a Task
should be added to a Pipeline.

## Helm

Helm is the last tool needed to deploy a Pipeline. We allow users to provide
custom values for the version of the Smithy components that they want to deploy
and the container image repository from where the images will be fetched. This
allows users to build all our images themselves with whatever base image they
prefer, and to pin their installations to a specific version. All these
variables can be trivially configured using Helm.

## Running a pipeline

A Tekton Pipeline is a template of a sequence of steps that produce a meaningful
result. The Tasks of the pipeline will almost certainly require some
parameterization. These parameters are passed to and instantiation of a Pipeline
using the PipelineRun object. You can check our examples folder to various ways
of combining our components to design pipelines for projects with a variety of
languages and frameworks.
