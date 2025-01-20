#!/bin/bash

set -xe

cd $1
go list -buildvcs=false -json -deps ./... >go-deps.json
cat go-deps.json | /nancy sleuth -o json > $2 || true
