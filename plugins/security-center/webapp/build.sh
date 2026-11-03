#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ -e node_modules ] || [ -L node_modules ]; then
  echo 'Remove the existing webapp/node_modules before using the locked host toolchain' >&2
  exit 1
fi
ln -s ../../../app/node_modules node_modules
trap 'unlink node_modules' EXIT HUP INT TERM
bun x eslint src vite.config.ts tests
bun x vite build --config vite.config.ts
bun x vue-tsc --noEmit -p tsconfig.json

bun test --isolate --max-concurrency=1 tests
