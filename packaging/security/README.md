# Security runtime

This is a separate image recipe; the root upstream Dockerfile remains unchanged.
See [deployment boundaries](../../docs/security-center.md).

1. Build the fork frontend and Linux amd64 binary using the project's release build.
   Copy that binary to `packaging/security/artifacts/nginx-ui`. Do not use an upstream
   release binary for the final image: it lacks this fork's Security Center/plugin host.
2. Pin a verified Debian base digest and snapshot. The following inputs were tested:

   ```sh
   export DEBIAN_BASE=debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
   export DEBIAN_SNAPSHOT=20261103T000000Z
   export SECURITY_IMAGE=nginx-ui-security:local
   sh packaging/security/build.sh
   ```

   Use a newer verified snapshot for security updates; a pinned snapshot does not
   automatically receive fixes. The helper stages only packaging inputs and bounds
   legacy Docker build containers to 3 GiB RAM, no swap. It needs Docker's legacy
   builder support; modern BuildKit deployments need an equivalently bounded builder.
3. Run the isolated request test (no published ports or external network):

   ```sh
   docker run --rm --name nginx-ui-security-smoke \
     --label codex.task=nginx-ui-security-runtime \
     --network none --memory=512m --memory-swap=512m --pids-limit=128 \
     --entrypoint /bin/sh \
     -v "$PWD/packaging/security/request-smoke.sh:/request-smoke.sh:ro" \
     nginx-ui-security:local /request-smoke.sh
   ```

   This validates normal JSON/XML, escaped JSON attacks, malformed JSON/XML,
   query-string CRS behavior and CrowdSec bouncer behavior with a
   **mock local LAPI**. It does not validate the UI, a real CrowdSec engine, plugin
   packages, certificates or the cluster's existing routes.
4. Provision initial WAF policy explicitly by copying the image's
   `/usr/local/share/nginx-ui-security/initial-policy.conf` to a **new** managed
   `/etc/nginx/security-center/modsecurity.conf`. Never overwrite an existing policy.
   Do NOT include a full ruleset in `http {}`: Security Center refuses that
   incompatible parent configuration. Apply the intended managed sites so their
   snippets reference individual complete policy files. Saving global defaults alone
   does not activate enforcement on unmanaged sites (see deployment guide).
   Mount persistent Nginx UI state and configure feature flags described in source
   `plugins/security-center/internal/center/config.go`. Enable only after scoped admin testing.

No auto-generated credentials, automatic policy activation, deployment or upstream
PR are performed by this recipe. CrowdSec scenario administration requires the
engine-side integration documented in the deployment guide.

Additional acceptance commands (same isolated flags as request smoke):

- Mount/run `startup-smoke.sh` with 768 MiB RAM and 256 PIDs to start the actual fork
  binary under supervisor, verify embedded UI delivery and reject anonymous security
  API access. This script requires an empty disposable state directory.

- Generate real backend fixtures using opt-in Go test `TestGenerateRuntimeFixtures`
  with `NGINX_UI_GENERATE_SECURITY_FIXTURES=true` and a writable `/security-fixtures`
  mount. Mount its resulting directory at the same path read-only in the runtime,
  then mount/run `generated-policy-smoke.sh`. This tests the actual service-generated
  files without rewriting them.
- Mount/run `vhost-smoke.sh` to verify two-host policy isolation, scoped exceptions,
  exact path blocks, CrowdSec enforcement selection, and audit minimization.
- Mount this directory at `/usr/local/lib/nginx-ui-security:ro` and run
  `python3 /usr/local/lib/nginx-ui-security/reader-process-smoke.py` in a disposable
  container to check the real reader process, persisted cursor and SIGTERM handling.
- `python3 -m unittest discover -s packaging/security -p 'test_audit*.py'` tests
  normalization, source attribution, bounded records and cursor/rotation behavior.

For shared collection enable `NGINX_UI_SECURITY_AUDIT_ENABLED=true`, inject
`NODE_NAME`, persist per-instance cursor state, and merge `security-events.alloy.example`
into the existing collector. See the deployment guide before activating. The reader
ingests ModSecurity audits and actual per-vhost CrowdSec enforcement events with
original timestamps. Central CrowdSec engine alerts/scenarios remain a separate
unconfigured feed; see the documented attribution and collection requirements.

For the optional separate-engine reporting integration, review `engine-adapter/`
and the deployment guide. `sharing-engine-smoke.sh` checks the official engine's
configuration handling entirely offline; it requires the verified engine binary
mounted at `/engine` and must run in a network-isolated disposable container.

## Signed Security Center package

After building the plugin executable and web bundle, run
`packaging/security/package-plugin.sh`. It stages only the manifest, documentation,
executable and browser assets. Signing keys live in ignored local lab state and
are never included. Install through the normal API with
`python3 packaging/security/local-cluster/install-plugin.py <package.tar.gz>`.
This helper is restricted to the three local test endpoints. Developer mode is
not required. The publisher is a locally trusted community publisher, not an
official upstream signer.
