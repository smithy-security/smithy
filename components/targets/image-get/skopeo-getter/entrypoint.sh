#!/bin/sh
set -e

check_var() {
  if [ -n "$1" ]; then
    res="$1"
    if [ -n "$2" ]; then
        echo "$res:$2"
    else
        echo $res
    fi
  else
    echo "' '"
  fi
}


creds=$(check_var $3 $4)
skopeo copy \
            --dest-tls-verify=false\
            --src-tls-verify=false\
            --src-creds="${creds}" \
            "docker://${1}"\
            "docker-archive:${2}"


