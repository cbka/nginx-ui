#!/bin/sh
set -eu
: "${RUNTIME_BASE:?Supply immutable production runtime image digest}"
case "$RUNTIME_BASE" in *@sha256:*) ;; *) echo 'Runtime base must use a digest' >&2; exit 1;; esac
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
image=${NGINX_IMAGE:-codex/nginx-ui-security:nginx-1.30.6}
context=$(mktemp -d)
trap 'rm -rf "$context"' EXIT HUP INT TERM
for file in build-in-container.sh compile.py nginx.sha256 sources.sha256 module-sources.lock Dockerfile; do cp "$root/$file" "$context/$file"; done
docker run --rm --memory=4g --memory-swap=4g --cpus=2 --pids-limit=256 \
  --label codex.task=nginx130-build --entrypoint sh \
  -e "BUILD_UID=$(id -u)" -e "BUILD_GID=$(id -g)" \
  -v "$context:/out" "$RUNTIME_BASE" /out/build-in-container.sh
rm -rf "$context/sources" "$context/nginx-1.30.6.tar.gz"
DOCKER_BUILDKIT=0 docker build --memory=4g --memory-swap=4g --cpu-period=100000 --cpu-quota=200000 \
  --build-arg "RUNTIME_BASE=$RUNTIME_BASE" --label codex.task=nginx130-runtime -t "$image" "$context"
