# Production compatibility preflight

## Runtime compatibility overlay

`Dockerfile` builds on an explicitly supplied, verified `SECURITY_BASE` image.
It installs the observed production runtime module versions from the base image’s
immutable Debian snapshot, recorded in `runtime-modules.lock`, and requires Nginx
`1.26.3-3+deb13u10` before and after installation. Nchan and the unused NDK development
headers are excluded. Existing Lua, ModSecurity and stream modules are explicitly
pinned too; the build fails on a version mismatch. The complete final package
inventory is written to `/usr/local/share/nginx-ui-security/packages.lock`.
It preserves the existing workload
entrypoint `/usr/local/sbin/nginx-ui-entrypoint` and application restart command
`/usr/local/sbin/nginx-ui-nginx-restart`, delegating to the fork's validation and
supervisor configuration. Existing app.ini and application database are untouched.

The captured production runtime disables Nchan due to a worker-start assertion
that can leave a shared-memory lock held. The overlay retains its exact-loader
tombstone policy, but defaults to read-only validation: an active Nchan loader
causes a clear startup refusal. Only set `NGINX_UI_ALLOW_NCHAN_TOMBSTONE=true`
on the **new deployment's independently cloned PVCs** to permit that narrow
existing policy. It removes no unrelated modules, enables no security hooks, and
does not edit live Lua sites. Already-disabled regular tombstones remain unchanged.

Build context is the repository root; no private snapshot/state is copied by
this Dockerfile. Keep the original deployment and PVCs intact. The old image uses
its own `/etc/supervisor/nginx-ui.conf`; the new aliases intentionally address the
new `/etc/supervisor/security-runtime.conf` through the base scripts.

## Isolated configuration check

This helper uses a **private copy**, never a live mount. It does not contact
Kubernetes, start Nginx UI, open a database, sync peers, or modify copied files.
Use the exact captured `/etc/nginx`, `/etc/nginx-local`, and `/var/www` trees,
preserving symlinks and file permissions, beneath one private snapshot directory.
Keep certificates and credentials outside Git and restrict access to the snapshot.

```sh
python3 packaging/security/production/preflight.py \
  --snapshot /private/snapshot \
  --image codex/nginx-ui-security:plugin-20261103 \
  --hosts /private/service-hosts.json
```

The optional hosts file is a JSON object, for example
`{"service.namespace.svc.cluster.local": "10.43.0.10"}`. Obtain addresses through
read-only cluster inspection. There is no automatic name discovery or network
access; the mappings enable syntax-time resolution only. Wildcards are unsupported.
The image must already exist locally (`--pull never`).

The disposable container has no network, a read-only root and copied mounts,
512 MiB memory with no swap, one CPU, 128 PIDs, and a 45-second command timeout.
Only temporary log/cache/run directories and Debian Nginx's `/var/lib/nginx`
request-buffer directory (32 MiB tmpfs) are writable. It overrides the image
entrypoint with `nginx -t`. The helper removes its uniquely named container even
on timeout. No persistent Docker volume or network is created.

The JSON report lists symlink destinations and configured dynamic-module paths;
`nginx -t` verifies their actual resolution and compatibility inside the image.
Targets outside the copied trees must exist in the image; host symlinks are never
dereferenced during inspection. Diagnostics deliberately omit raw Nginx messages,
which may contain secret directive values; error category and configuration
location are reported where available. Exit status: 0 success, 1 compatibility
failure/timeout, 2 invalid input or unavailable local runtime.

## Acceptance plan

1. Capture the selected peer's trees privately and retain rollback configuration,
   old image digest, deployment spec, certificates and application-state backup.
2. Run this preflight against the new image. Resolve all missing modules, paths,
   symlinks and DNS mappings. Success means syntax/file compatibility only.
3. Before rollout, verify plugin support, initialized application storage, module
   parity, updater ownership, restart command and per-peer persistent storage.
4. Test a dedicated live canary later: normal request, DetectionOnly event,
   scoped WAF block and temporary CrowdSec decision, then remove that decision.
   Confirm correct client IP, centralized events and peer attribution.
5. Verify explicit plugin off/on retains desired policy and reverses enforcement
   on each tested peer. Confirm rollback restores both image and configuration;
   image rollback alone can leave unsupported Lua/module directives behind.
6. Only after canary acceptance proceed with the separately coordinated rollout.
   The helper itself never deploys or changes production.

## Host version metadata (required before packaging)

The frontend build must generate its version **before bundling imports**. The
Vite build-id plugin therefore uses `prepare: true`, including local builds where
`CI` is unset. Its source of truth is `app/package.json`; overriding only the Go
version produces a false node-compatibility warning and incorrect plugin host
metadata.

1. Run `python3 packaging/security/production/version_metadata.py prepare --version 3.0.0-security.4`
   (substitute the intended release). This updates the package version, never an
   already-built frontend.
2. Build the frontend using the task's bounded build runner. The build writes
   matching `app/src/version.json` and `app/dist/version.json`.
3. Run `python3 packaging/security/production/version_metadata.py generate`.
   This rejects missing/stale/mismatched build metadata, then generates the Go
   version initializer from that exact frontend build and the Git commit hash.
4. Compile the host with that generated initializer and the newly built embedded
   frontend. Do not separately override `version.Version`, build IDs, or hash.
   A build-time timestamp is independent and may still be passed through ldflags.
5. Before rollout, compare the host version endpoint and the served frontend's
   `version.json`; the version and build IDs must match. Package the verified host
   binary using `Dockerfile.host` and set `HOST_VERSION` to the same release.

The helper does not build, deploy, rewrite compiled bundles or alter live
configuration. Regression checks: `python3 -m unittest discover -s
packaging/security/production -p test_version_metadata.py`.
