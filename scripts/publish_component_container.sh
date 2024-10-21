#!/bin/bash

set -e

source ./scripts/util.sh

if [ "$#" -eq 0 ]
then
    util::error "No directory provided to build"
    exit 1
fi

if make -C $(dirname "${1}") --no-print-directory --dry-run publish >/dev/null 2>&1
then
	make -C $(dirname "${1}") --no-print-directory --quiet publish CONTAINER_REPO="${CONTAINER_REPO}" SMITHY_VERSION="${SMITHY_VERSION}"
else
	docker push "${CONTAINER_REPO}/$(dirname ${1}):${SMITHY_VERSION}" 1>&2
fi

if make -C $(dirname "${1}") --no-print-directory --dry-run publish-extras >/dev/null 2>&1
then
	make -C $(dirname "${1}") --no-print-directory --quiet publish-extras CONTAINER_REPO="${CONTAINER_REPO}" SMITHY_VERSION="${SMITHY_VERSION}"
fi
