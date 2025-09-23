#!/bin/bash

set -xe
export ERL_FLAGS="-noinput -noshell"
export TERM="dumb"
export PATH=$PATH:$HOME/.mix/escripts

cd $1
credo list --format=sarif | tee $2
