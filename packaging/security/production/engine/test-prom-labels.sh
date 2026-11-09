#!/bin/sh
# Real CrowdSec parser/enrichment regression, fully isolated from production.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
image=${1:?Pass an existing production engine image}
docker run --rm --network none --memory 512m --memory-swap 512m --cpus 1 \
  --label codex.task=crowdsec-parser-regression \
  -v "$here:/fixture:ro" --entrypoint sh "$image" -c '
set -eu
cp -a /usr/share/nginx-security-engine/config/. /etc/crowdsec/
cp -a /usr/share/nginx-security-engine/data/. /var/lib/crowdsec/data/
cp /fixture/nginx-prom-labels-parser.yaml /etc/crowdsec/parsers/s01-parse/nginx-prom-labels.yaml
cscli machines add parser-fixture --password fixture-only --url http://127.0.0.1:8080 --file /etc/crowdsec/local_api_credentials.yaml >/dev/null
crowdsec -no-cs -no-capi >/tmp/fixture-lapi.log 2>&1 &
lapi=$!
trap "kill $lapi 2>/dev/null || true" EXIT
python3 /fixture/prom_labels_runtime_check.py
'
