#!/bin/bash

set -xe
export PATH=$PATH:$HOME/.mix/escripts

cd $1
credo list --format=sarif | tee $2
