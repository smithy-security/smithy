#!/bin/sh

set -ex

apt-get update
apt-get upgrade -y
apt-get install -y wget

GO_VERSION=$(cat go.mod | grep -E "^go 1\.[0-9]+\.[0-9]+$" | sed 's/go //')
cd /tmp && wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
rm -rf /usr/local/go
tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz

export PATH=$PATH:/usr/local/go/bin
userdel --remove --force ${EXTERNAL_UID} || true
useradd --uid ${EXTERNAL_UID} --no-user-group --no-create-home --non-unique qauser

exec $@
