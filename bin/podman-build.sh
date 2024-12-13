#!/usr/bin/env bash

GIT=$(which git 2>/dev/null)
test -z "${GIT}" && echo "No 'git' command found in the PATH." && log_hint "Use 'brew install git' to install it." && exit

PODMAN=$(which podman 2>/dev/null)
test -z "${PODMAN}" && echo "No 'podman' command found in the PATH." && log_hint "Use 'brew install podman' to install it." && exit

git_repo_owner=$(${GIT} config --get remote.origin.url | rev | cut -d'/' -f2 | rev)
git_repo=$(      ${GIT} config --get remote.origin.url | rev | cut -d'/' -f1 | rev | cut -f1 -d'.')

image=${git_repo_owner}/${git_repo}

${PODMAN} build -t ${image}:latest .
