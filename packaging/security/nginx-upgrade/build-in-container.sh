#!/bin/sh
set -eu
: "${BUILD_UID:?Caller uid required}" "${BUILD_GID:?Caller gid required}"
trap 'chown -R "$BUILD_UID:$BUILD_GID" /out' EXIT
# /out contains explicit build inputs only; base retains immutable Debian sources.
sed 's/^deb /deb-src /' /etc/apt/sources.list > /tmp/nginx-source-list
cat /tmp/nginx-source-list >> /etc/apt/sources.list
rm /tmp/nginx-source-list
apt-get update -qq
xargs apt-get build-dep -y --no-install-recommends < /out/module-sources.lock
mkdir -p /out/sources
cd /out/sources
xargs apt-get source --download-only < ../module-sources.lock
sha256sum -c ../sources.sha256
for file in *.dsc; do dpkg-source -x "$file"; done
cd /out
curl -fsSL https://nginx.org/download/nginx-1.30.6.tar.gz -o nginx-1.30.6.tar.gz
sha256sum -c nginx.sha256
python3 /out/compile.py
