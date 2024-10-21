#!/bin/bash

set -e;

source ./scripts/util.sh

# Sanity check for not arguments being passed.
if [ "$#" -eq 0 ]
then
    util::error "No directory argument provided to build."
    exit 1
fi

dir_name="$1"
GOOS="${GOOS}"
GOARCH="${GOARCH}"
build_architecture="${GOOS}/${GOARCH}"

executable=$(basename $(dirname ${dir_name}))

echo ${dir_name} | grep -Eq ^components/producers/.*$ && executable="${executable}-parser" || true
echo ${dir_name} | grep -Eq ^components/enrichers/.*$ && executable="${executable}" || true
echo ${dir_name} | grep -Eq ^components/consumers/.*$ && executable="${executable}" || true

EXECUTABLE_SRC_PATH="$(dirname ${dir_name})/${build_architecture}/${executable}"
COMPONENT_PATH="$(dirname ${dir_name})"
EXECUTABLE_TARGET_PATH="${COMPONENT_PATH}/${executable}"

BASE_IMAGE_PATH=$(realpath ${BASE_IMAGE_PATH:-./containers/Dockerfile.base})

if make -C "${COMPONENT_PATH}" --no-print-directory --dry-run container >/dev/null 2>&1
then
    make -C "${COMPONENT_PATH}" --no-print-directory --quiet container BASE_IMAGE_PATH="${BASE_IMAGE_PATH}" CONTAINER_REPO="${CONTAINER_REPO}" SMITHY_VERSION="${SMITHY_VERSION}" BUILD_ARCHITECTURE="${build_architecture}"
else
    docker build \
        --build-arg EXECUTABLE_SRC_PATH="${EXECUTABLE_SRC_PATH}" \
        --build-arg EXECUTABLE_TARGET_PATH="${EXECUTABLE_TARGET_PATH}" \
        --tag "${CONTAINER_REPO}/${COMPONENT_PATH}:${SMITHY_VERSION}" \
        $([ "${SOURCE_CODE_REPO}" != "" ] && echo "--label=org.opencontainers.image.source=${SOURCE_CODE_REPO}" ) \
        --file "${BASE_IMAGE_PATH}" \
        --platform "${build_architecture}" \
        ./bin
fi

if make -C "${COMPONENT_PATH}" --no-print-directory --dry-run extras >/dev/null 2>&1
then
    make -C "${COMPONENT_PATH}" --no-print-directory --quiet extras CONTAINER_REPO="${CONTAINER_REPO}" SMITHY_VERSION="${SMITHY_VERSION}"
fi
