#! /bin/sh
set -xe

echo "Running osv-scanner with args {$@} sending output to ${RAW_OUT_FILE}" 
/go/bin/osv-scanner $@ | tee ${RAW_OUT_FILE}
