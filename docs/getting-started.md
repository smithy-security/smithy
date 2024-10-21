# Getting Started with Smithy

This guide will help to quickly setup Smithy on a Kubernetes cluster and get a
pipeline running. The first step is to create a dev Kubernetes cluster in order
to deploy Tekton. We suggest you use KiND to provision a local test cluster
quickly. If you already have a Kubernetes cluster then, you can follow the
steps highlighted on [Setup Smithy on another Kubernetes engine (Not recommended)](./setup-smithy-in-custom-k8s-engine.md).

We support two ways of deploying Smithy:

1. Using the Helm packages that we distribute, like shown in this document.
2. Using your local copy of this repository.
   Useful when you are developing components or new functionality.
   Please see [Custom Components](./custom-components.md)
   to learn more about this.

## Tools you will need

You will need to have the following tools installed in your system:

1. [KiND](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)
2. [kustomize](https://kubectl.docs.kubernetes.io/installation/kustomize/)
3. [Docker](https://docs.docker.com/engine/install/)
4. [Helm](https://helm.sh/docs/intro/install/)
5. [Go](https://go.dev/)

## Deploying an example pipeline with Smithy

Following the steps below, we'll deploy an example Golang project
pipeline which will:

* Clone a Golang repository.
  This can be changed by updating the `git-clone-url`
  parameter in [pipelinerun.yaml](../examples/pipelines/golang-project)
* Scan the repository with [gosec](https://github.com/securego/gosec)
  and [nancy](https://github.com/sonatype-nexus-community/nancy)
* Enrich the findings with CODEOWNERS annotation
* Report the enriched results on [MongoDB](https://github.com/mongodb/mongo)
  and [ElasticSearch](https://github.com/elastic/elasticsearch)

### Set up Smithy and its dependencies

You can set up Smithy and its dependencies by executing `make install`.

This command will:

* spin up a Kubernetes cluster in Docker using [KinD](https://kind.sigs.k8s.io/).
  TBD - if not KIND
* deploy Smithy dependencies and Custom Resource Definitions (CRDs).
  Most of these dependencies are required by the example pipelines:
  * MongoDB
  * Elasticsearch
  * Kibana
  * MongoDB
  * Postgres

All the dependencies are built using smithy's current [latest release](https://github.com/smithy-security/smithy/tags).

This will take a while, so we invite you to go and grab a coffee!

```text
   )  (
  (   ) )
   ) ( (
  -------
.-\     /
'- \   /
  _______
```

`espresso cup by @ptzianos`

### Deploy a pipeline

For example, we can deploy a pipeline for the `golang-project`.

You can do so by executing `./bin/cmd/path/to/smithyctl ./examples/pipelines/golang-project`.

### Execute a pipeline

You can execute `kubectl create -n smithy -f ./examples/pipelines/golang-project/pipelinerun.yaml`.

### Watch the pipeline execute

You can follow the progress of the pipeline by checking
`Pods`,`PipelineRuns` and `TaskRuns` on `smithy`'s namespace.

Pipelines (`PipelineRuns`) are executed by multiple Tasks (`TaskRuns`)
which are deployed in containers running in pods.

You can monitor the status of a pipeline by executing:

```shell
kubectl get pipelineruns -w -n smithy
NAME                          SUCCEEDED   REASON    STARTTIME   COMPLETIONTIME
smithy-golang-project-7hqmc   True        Succeeded 24m         14m
```

And of its tasks by executing:

```shell
kubectl get taskruns -w -n smithy
NAME                                                 SUCCEEDED   REASON      STARTTIME   COMPLETIONTIME
smithy-golang-project-7hqmc-base                     True        Succeeded   27m         26m
smithy-golang-project-7hqmc-consumer-elasticsearch   True        Succeeded   23m         23m
smithy-golang-project-7hqmc-consumer-mongodb         True        Succeeded   23m         17m
smithy-golang-project-7hqmc-enricher-aggregator      True        Succeeded   24m         23m
smithy-golang-project-7hqmc-enricher-codeowners      True        Succeeded   24m         24m
smithy-golang-project-7hqmc-git-clone                True        Succeeded   27m         25m
smithy-golang-project-7hqmc-producer-aggregator      True        Succeeded   24m         24m
smithy-golang-project-7hqmc-producer-golang-gosec    True        Succeeded   25m         24m
smithy-golang-project-7hqmc-producer-golang-nancy    True        Succeeded   25m         24m
```

Finally, monitor the pods executing such tasks by executing:

```shell
kubectl get pods -w -n smithy
NAME                                                     READY   STATUS      RESTARTS   AGE
smithy-es-default-0                                      1/1     Running     0          24m
smithy-golang-project-7hqmc-base-pod                     0/1     Completed   0          22m
smithy-golang-project-7hqmc-consumer-elasticsearch-pod   0/1     Running     0          19m
smithy-golang-project-7hqmc-consumer-mongodb-pod         0/1     Running     0          19m
smithy-golang-project-7hqmc-enricher-aggregator-pod      0/2     Completed   0          19m
smithy-golang-project-7hqmc-enricher-codeowners-pod      0/2     Completed   0          19m
smithy-golang-project-7hqmc-git-clone-pod                0/2     Completed   0          22m
smithy-golang-project-7hqmc-producer-aggregator-pod      0/3     Completed   0          19m
smithy-golang-project-7hqmc-producer-golang-gosec-pod    0/3     Completed   0          21m
smithy-golang-project-7hqmc-producer-golang-nancy-pod    0/4     Completed   0          21m
smithy-kb-5df6fcb8c7-tsbg6                               1/1     Running     0          23m
smithy-postgresql-0                                      1/1     Running     0          25m
```

You can then check the enriched results stored in MongoDB and Elasticsearch.

### Debugging

If a few task don't complete, you can check their logs.

Usually you can simply tail the logs of an erroring pod
associated with such task by executing:

```shell
kubectl logs $podName $stepName 
```

For any error that is not related with some of you testing, please reach out.

## Develop a custom component

Now that you have completed our introduction, you can explore how to extend
Smithy for you needs by building your first component or pipeline.

Please check out [this document](./custom-components.md) to learn more!
