# Setup Smithy on another Kubernetes engine (Not recommended)

If you don't want to use [KiND](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)
locally, you can follow these steps to deploy Smithy and it's dependencies.

If you follow the [Getting Started](./getting-started.md) guide,
all these steps are taken care of by the `make install` command.

## Deploying Smithy dependencies

Smithy dependencies are split into two categories:

1. Dependencies that the system can't work without
2. Dependencies that the system doesn't need but are probably needed by most
   pipelines.

The dependency that Smithy can't function without is [Tekton](https://tekton.dev/)
and for many users
it is a good idea to deploy the Tekton Dashboard too for better visibility into
what's happening on the cluster. We offer a simple way of deploying these along
with an Nginx ingress controller with the command:

```bash
make dev-infra
```

## Deploying Smithy Pipeline dependencies using Helm packages

1. Deploy the Helm packages

> :warning: **Warning 2:** make sure that you have all the needed tools
> listed in the previous section installed in your system

For Smithy pipelines to run, they usually require the following services:

1. MongoDB
2. Elasticsearch
3. Kibana
4. MongoDB
5. Postgres

We use the Elastic Operator to spin up managed instances of Elasticsearch and
Kibana and the bitnami charts to deploy instances of PostgreSQL and MongoDB.

If you run the command:

```bash
make dev-smithy
```

You will deploy the Elastic Operator on the cluster and the Smithy Helm
package. Depending on the capabilities of your workstation this will probably
take a couple of minutes, it's perfect time to go get a cup of coffee ;).

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

The Smithy Helm package lists as dependencies the Bitnami charts for Postgres
and MongoDB. The values used are in the `deploy/smithy/values/dev.yaml` file.

1. Expose the TektonCD Dashboard

```bash
kubectl -n tekton-pipelines port-forward svc/tekton-dashboard 9097:9097
```

2. Expose the Kibana Dashboard.

```bash
# Use `kubectl port-forward ...` to access the Kibana UI:
kubectl -n smithy port-forward svc/smithy-kb-kibana-kb-http 5601:5601
# You can obtain the password by examining the 
# `smithy-es-elasticsearch-es-elastic-user` secret:
# The username is `elastic`.
kubectl -n smithy get secret smithy-es-elasticsearch-es-elastic-user \
  -o=jsonpath='{.data.elastic}' | \
  base64 -d && \
  echo
```

3. Expose the Kibana Dashboard

```bash
 # Use `kubectl port-forward ...` to access the Kibana UI:
 kubectl -n smithy port-forward svc/smithy-kb-kibana-kb-http 5601:5601
```

The username/password is the same as Kibana

## Deploy Smithy components

The components that are used to build our pipelines are comprised out of two
pieces:

1. a wrapper around the binary of the tool that we wish to execute packaged
   into a container.
2. a Tekton Task file that describes how to execute the component.

We provide Helm packages with all our components that can be easily installed
as follows:

```bash
helm upgrade \
  --install \
  --namespace smithy \
  --values deploy/smithy/values/dev.yaml \
  smithy-security-oss-components \
  oci://ghcr.io/smithy-security/smithy/charts/smithy-security-oss-components 
```

## Applying manually migrations

There some migrations that should be applied to the postgres instance so that
the enrichment components can store and retrieve data from it. In order to apply
the migrations you need to run the following command (the container with the
`smithyctl` binary and the migration scripts was built and pushed in the
previous step):

```bash
kubectl apply -n smithy -f deploy/smithy/serviceaccount.yaml
kubectl apply -n smithy -f deploy/smithy/role.yaml
kubectl apply -n smithy -f deploy/smithy/rolebinding.yaml
make cmd/smithyctl/bin

export SMITHYCTL_MIGRATIONS_PATH='/etc/smithy/migrations/enrichment'
bin/cmd/smithyctl migrations apply \
  --namespace smithy \
  --as-k8s-job \
  --image "${CONTAINER_REPO}/smithyctl:${CUSTOM_SMITHY_VERSION}" \
  --url "postgresql://smithy:smithy@smithy-enrichment-db.smithy.svc.cluster.local?sslmode=disable" \
```
