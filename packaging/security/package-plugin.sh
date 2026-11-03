#!/bin/sh
# Package only distributable plugin assets. Signing keys stay outside staging.
set -eu
umask 077
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
plugin="$root/plugins/security-center"
: "${PLUGIN_PACKER:=$root/packaging/security/artifacts/nginx-ui}"
: "${PLUGIN_SIGNING_DIR:=$root/packaging/security/local-cluster/state/plugin-signing}"
: "${PLUGIN_OUTPUT_DIR:=$root/packaging/security/artifacts/plugins}"
test -x "$PLUGIN_PACKER"
test -s "$plugin/server/security-center"
test -s "$plugin/webapp/dist/main.js"
test -s "$plugin/webapp/dist/style.css"
mkdir -p "$PLUGIN_OUTPUT_DIR"
if [ ! -e "$PLUGIN_SIGNING_DIR" ]; then
    mkdir -p "$PLUGIN_SIGNING_DIR"
    "$PLUGIN_PACKER" plugin key init --id io.github.mctdatapool.security-center --out "$PLUGIN_SIGNING_DIR"
fi
for file in primary.pub signing.key plugin.signer plugin.signer.minisig; do
    test -s "$PLUGIN_SIGNING_DIR/$file"
done
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM
mkdir -p "$stage/server" "$stage/webapp/dist"
for file in plugin.json README.md LICENSE; do cp "$plugin/$file" "$stage/$file"; done
cp "$plugin/server/security-center" "$stage/server/security-center"
cp "$plugin/webapp/dist/main.js" "$stage/webapp/dist/main.js"
cp "$plugin/webapp/dist/style.css" "$stage/webapp/dist/style.css"
cp "$PLUGIN_SIGNING_DIR/plugin.signer" "$PLUGIN_SIGNING_DIR/plugin.signer.minisig" "$stage/"
version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$plugin/plugin.json")
case "$version" in *[!a-zA-Z0-9.+-]*|'') echo 'Invalid plugin version' >&2; exit 1;; esac
output="$PLUGIN_OUTPUT_DIR/io.github.mctdatapool.security-center-$version-linux-amd64.tar.gz"
"$PLUGIN_PACKER" plugin pack "$stage" "$output" --key "$PLUGIN_SIGNING_DIR/signing.key"
"$PLUGIN_PACKER" plugin lint "$output"
printf '%s\n' "$output"
