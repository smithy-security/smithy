#!/bin/bash

# based on the script from KiND docs

set -o errexit

reg_name='kind-registry'
reg_port='5000'
cluster_name='smithy-demo'

source ./scripts/util.sh

while getopts n:p:c: flag
do
    case "${flag}" in
        u) reg_name=${OPTARG};;
        p) reg_port=${OPTARG};;
        c) cluster_name=${OPTARG};;
        *) util::error "unknown flag ${flag}"; exit 1;;
    esac
done

# 1. Create registry container unless it already exists
if [ "$(docker inspect -f '{{.State.Running}}' ${reg_name} 2>/dev/null)" != "true" ]
then
  util::info "Spinning up container with Docker registry"
  docker run --detach \
            --restart=always \
            --publish "127.0.0.1:${reg_port}:${reg_port}" \
            --network bridge \
            --name "${reg_name}" \
            registry:2
fi

# 2. Create kind cluster with containerd registry config dir enabled
if ! kind get clusters 2>&1 | grep "${cluster_name}"
then
  cat <<EOF | kind create cluster --name ${cluster_name} --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry]
    config_path = ""
  [plugins."io.containerd.grpc.v1.cri".registry.auths]
  [plugins."io.containerd.grpc.v1.cri".registry.configs]
    [plugins."io.containerd.grpc.v1.cri".registry.configs."${reg_name}:${reg_port}".tls]
      insecure_skip_verify = true
  [plugins."io.containerd.grpc.v1.cri".registry.headers]
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors]
    [plugins."io.containerd.grpc.v1.cri".registry.mirrors."${reg_name}:${reg_port}"]
      endpoint = ["http://${reg_name}:${reg_port}"]
EOF

  # 3. Connect the registry to the cluster network if not already connected
  # This allows kind to bootstrap the network but ensures they're on the same network
  if [ "$(docker inspect -f='{{json .NetworkSettings.Networks.kind}}' "${reg_name}")" = 'null' ]
  then
    util::info "Connecting KiND cluster container to the registry container"
    docker network connect "kind" "${reg_name}"
  fi
fi

# 5. Document the local registry
# https://github.com/kubernetes/enhancements/tree/master/keps/sig-cluster-lifecycle/generic/1755-communicating-a-local-registry
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "${reg_name}:${reg_port}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF
