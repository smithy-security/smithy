#!/bin/sh
set -ex

check_tar() {
  if [[ "$1" == *.tar* ]]; then
    echo "--input=${1}"
  else
    echo ""
  fi
}

input=$(check_tar $2)

/usr/local/bin/trivy image \
   --detection-priority=precise \
   --parallel=0 \
   --format=sarif \
   --scanners=vuln \
   --scanners=misconfig \
   --scanners=secret \
   --scanners=license \
   --timeout=30m \
   --output="${1}" \
   $input \
   "${2}"
