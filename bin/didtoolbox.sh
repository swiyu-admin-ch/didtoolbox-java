#!/usr/bin/env bash

GIT=$(which git 2>/dev/null)
test -z "${GIT}" && echo "No 'git' command found in the PATH." && log_hint "Use 'brew install git' to install it." && exit

PODMAN=$(which podman 2>/dev/null)
test -z "${PODMAN}" && echo "No 'podman' command found in the PATH." && log_hint "Use 'brew install podman' to install it." && exit

git_repo_owner=$(${GIT} config --get remote.origin.url | rev | cut -d'/' -f2 | rev)
git_repo=$(      ${GIT} config --get remote.origin.url | rev | cut -d'/' -f1 | rev | cut -f1 -d'.')

image=${git_repo_owner}/${git_repo}

# CAUTION The arch MUST be appropriate for the libdidresolver.so shared library (as part of didresolver.jar).
#         Otherwise, when building on a machine with arm64 CPU (e.g. on macOS M1/M2 ARM64 CPU), you should see
#         "WARNING: image platform (linux/amd64) does not match the expected platform (linux/arm64)"
${PODMAN} run --arch=amd64 -v $(pwd):$(pwd):z,exec -v /var/tmp:/var/tmp:z,exec -w $(pwd) ${image}:latest "$@"
