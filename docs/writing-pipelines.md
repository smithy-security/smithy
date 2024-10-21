# Writing Your Own Pipeline

Composing pipelines is easy, just 4 steps.

1. Write a `kustomization.yaml` file pointing to the components you want to use.
2. Run `smithyctl pipelines build <path/to/kustomization.yaml>` and redirect the
   output to a yaml file. This automatically collects all the component yamls to
   a single templated file.
3. Write a helm `Chart.yaml` for your pipeline
4. Write a pipelineRun.yaml providing values for your pipeline

## Example

Let's assume we want to scan a repository, that contains code written in Go.
Since we are scannign Go it makes sense to also enrich the results by detecting
duplicates and as a bonus let's also apply a Rego policy.
We can compose this pipeline by writing the following `kustomization.yaml`

In the following file:

* we tell `smithyctl` that we want the pipeline pods to have the suffix
  `*-golang-project`
* it should base everything to the official `task.yaml` and `pipeline.yaml`
* it should start by running a `git clone` to bring the code in for scanning
* it should scan the code with the `nancy` and `gosec` components.
* it should aggregate the scanning results
* enrich the results by applying policy and deduplicating
* it should aggregate the enriched results
* finally `smithyctl` should push results to `mongodb` and `elasticsearch`

```yaml
---
# file: go-pipeline/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
nameSuffix: -go-pipeline
components:
  - /components/sources/git
  - /components/producers/aggregator
  - /components/producers/golang-gosec
  - /components/producers/golang-nancy
  - /components/enrichers/aggregator
  - /components/enrichers/policy
  - /components/enrichers/deduplication
  - /components/consumers/mongodb
  - /components/consumers/elasticsearch
```

Then executing `smithyctl pipelines build ./go-pipeline/kustomization.yaml > ./go-pipeline/templates/all.yaml`
generates a Helm template.
To make the template into a chart we create the following `Chart.yaml`

```yaml
# file: ./go-pipeline/Chart.yaml
apiVersion: v2
name: "smithy-golang-project"
description: "A Helm chart for deploying a Smithy pipeline for a Golang project."
type: "application"
version: 0.0.1
appVersion: "0.0.1"
```

We can manage this chart as any other Helm chart and install it with:

```bash
helm upgrade go-pipeline ./go-pipeline --install \
     --set "image.registry=kind-registry:5000/smithy-security/smithy" \
     --set "smithy_os_component_version=$(make print-SMITHY_VERSION)"
```

and that's it!

## Running a pipeline

To run a pipeline you need a `pipelinerun.yaml` which binds values to the
component variables and instructs k8s to run the relevant pipeline.
For the pipeline above we can use the following `pipelinerun.yaml`

```yaml
# file: ./go-pipeline/pipelinerun/pipelinerun.yaml
---
apiVersion: tekton.dev/v1beta1
kind: PipelineRun
metadata:
  generateName: go-pipeline-
spec:
  pipelineRef:
    name: go-pipeline
  params:
  - name: git-clone-url
    value: <Your Git URL>
  - name: git-clone-subdirectory
    value: source-code
  workspaces:
  - name: output
    volumeClaimTemplate:
      spec:
        accessModes:
          - ReadWriteOnce
        resources:
          requests:
            storage: 1Gi
```

In this pipelinerun we provide the minimal values required to run the components
, namely a `git-clone-url` pointing to the repository we want to clone.
You can provide more values and customize the components more by providing the
relevant values as shown in each component documentation.

This pipelinerun can be triggered with:
`cat ./go-pipeline/pipelinerun/pipelinerun.yaml | kubectl create -f -`

You can monitor this pipeline's execution either in the Tekton dashboard or
using `kubectl get po -w`
