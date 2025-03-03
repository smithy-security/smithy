#! /usr/bin/env bash

set -xe
# run zap in daemon mode
echo 'Starting Zap, long output incoming'
/zap/zap.sh -daemon -silent -notel -config api.key=changeme -port 8081&
echo 'Sleeping 15 seconds to let zap init'
sleep 15

echo 'Running Orchestration'
# run orchestration script
export HTTP_PROXY='http://localhost:8081'
export HTTPS_PROXY='http://localhost:8081'
cd /workdir
source ./venv/bin/activate
python zap-orchestration.py



