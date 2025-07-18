#!/bin/bash

set -xe
export PATH=$PATH:$HOME/.mix/escripts

cd $1
sobelow --format=sarif | tee $2
