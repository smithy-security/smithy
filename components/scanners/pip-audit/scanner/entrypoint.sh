#! /bin/bash
set -xe
base=$(pwd)
for dep in $(find $1 -type f \( -iname "$3" -o -iname "$4" \) ); do
    echo "found file $dep, scanning"
    pip-audit \
        -f=json \
        --progress-spinner=off \
        --fix \
        -v \
        --output="$2/pipaudit.out.json" \
        -r $dep
done
