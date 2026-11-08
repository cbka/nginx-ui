#!/bin/sh
set -eu
: "${DEBIAN_BASE:?Set debian:trixie-slim@sha256 digest}"
: "${DEBIAN_SNAPSHOT:?Set immutable Debian snapshot timestamp}"
case "$DEBIAN_BASE" in debian:trixie-slim@sha256:*) ;; *) echo 'Require digest-pinned Debian trixie base' >&2; exit 1;; esac
case "$DEBIAN_SNAPSHOT" in *[!0-9TZ]*|'') echo 'Invalid snapshot timestamp' >&2; exit 1;; esac
image=${SECURITY_IMAGE:-nginx-ui-security:local}
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
test -s "$root/packaging/security/artifacts/nginx-ui"
context=$(mktemp -d)
trap 'rm -rf "$context"' EXIT HUP INT TERM
# Explicit allowlist: never copy local-cluster state, credentials, logs or test data.
mkdir -p "$context/packaging/security/artifacts"
for file in Dockerfile audit_reader.py audit_normalizer.py security-access.lua nginx_ui_appsec.lua nginx_ui_request_reference.lua request-reference-header.lua request-reference-body.lua request-correlation.conf nginx_ui_ip_allowlist.lua nginx_ui_security_events.lua crowdsec-init.conf entrypoint.sh restart.sh smoke.sh supervisord.conf modsecurity-base.conf loader.conf initial-policy.conf; do
    cp "$root/packaging/security/$file" "$context/packaging/security/$file"
done
cp "$root/packaging/security/artifacts/nginx-ui" "$context/packaging/security/artifacts/nginx-ui"
# Legacy builder enforces these resource limits per build container; no compilation here.
DOCKER_BUILDKIT=0 docker build --memory=3g --memory-swap=3g \
    --label codex.task=nginx-ui-security-runtime \
    --build-arg "DEBIAN_BASE=$DEBIAN_BASE" --build-arg "DEBIAN_SNAPSHOT=$DEBIAN_SNAPSHOT" \
    -t "$image" -f "$context/packaging/security/Dockerfile" "$context"
