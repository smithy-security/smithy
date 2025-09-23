#!/bin/bash

set -xe
export ERL_FLAGS="-noinput -noshell"
export TERM="dumb"
export PATH=$PATH:$HOME/.mix/escripts

cd $1
sobelow --format=sarif | tee $2
