#!/usr/bin/env bash

GIT=$(which git 2>/dev/null)
test -z "${GIT}" && echo "No 'git' command found in the PATH." && log_hint "Use 'brew install git' to install it." && exit

PODMAN=$(which podman 2>/dev/null)
test -z "${PODMAN}" && echo "No 'podman' command found in the PATH." && log_hint "Use 'brew install podman' to install it." && exit

git_repo_owner=$(${GIT} config --get remote.origin.url | rev | cut -d'/' -f2 | rev)
git_repo=$(      ${GIT} config --get remote.origin.url | rev | cut -d'/' -f1 | rev | cut -f1 -d'.')

image=${git_repo_owner}/${git_repo}

#arch=amd64
arch=arm64/v8

test -n "${DIDTOOLBOX_BOOTCLASSPATH}" && bootclasspath_podman_opts="-v ${DIDTOOLBOX_BOOTCLASSPATH}:${DIDTOOLBOX_BOOTCLASSPATH} -e DIDTOOLBOX_BOOTCLASSPATH=${DIDTOOLBOX_BOOTCLASSPATH}"

${PODMAN} run \
    --arch=${arch} \
    -v $(pwd):$(pwd):z,exec \
    -v /var/tmp:/var/tmp:z,exec \
    -w $(pwd) \
    ${bootclasspath_podman_opts} \
    ${image}:latest \
    "$@"
