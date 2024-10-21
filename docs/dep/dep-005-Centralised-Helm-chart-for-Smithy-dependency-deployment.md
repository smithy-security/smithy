# Centralised Helm chart for Smithy dependency deployment

## The problem

Currently the project relies on helm installing several helm Charts,
required for the various dependencies.
However, other parts of the project such as the project components themselves
and migrations are a combination of Helm Charts (components) and k8s yamls
applied through `smithyctl` (migrations). This is confusing
and tech debt since it is not clear what installs what, how and why.
It is suggested that migrations and the migrations job also become a Helm Chart.

## Changes suggested

The following changes are suggested

* Make a `smithy-dev` chart which installs all the sub-charts referenced by
  the `dev-deploy ` target
* Make a `smithy` chart which installs smithy components and migrations only
  assuming there are prerequisite systems present (Elasticsearch, Postgres etc),
  values for those systems are provided through `values.yaml`

## Tekton

Tekton sadly does not have an official Helm Chart.
While we still use tekton it is suggested to move our own tekton chart into a
new public repository and maintain it from there.
This approach keeps our repository clean and allows us to make use of a tekton
helm package

## Benefits

This approach allows for maximum extensibility and configurability.
e.g. Adding private components is an extra line in the Chart, adding migrations
is just running another chart with another post-job that depends on the original
smithy.

This approach is also testable as there are lots of Helm test utils and allows
for flexibility in both deployment and piecing together our many
(often optional) moving parts.
