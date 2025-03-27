#! /usr/bin/env bash

set -xe
# run zap in daemon mode
echo 'Starting Zap, long output incoming'
/zap/zap.sh -daemon -silent -notel -config api.key="${1}" -host localhost -port 8090&
echo 'Sleeping 15 seconds to let zap init'
sleep 15

echo 'Running Orchestration'
# run orchestration script
export HTTP_PROXY='http://localhost:8090'
export HTTPS_PROXY='http://localhost:8090'
cd /workdir
source ./venv/bin/activate
python zap-authenticated-scan.py



