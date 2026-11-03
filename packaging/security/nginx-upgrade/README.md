# NGINX 1.30.6 runtime upgrade

Build against the immutable existing production runtime, retaining the host,
CrowdSec bouncer, CRS, libraries and all 29 dynamic-module names/config paths.
This is an upstream source build, **not** a Debian NGINX package version bump.

```sh
RUNTIME_BASE='codex/nginx-ui-security@sha256:2a932793e90a93d9ba8b27e3da20e81b396f42bd505fed1b4dd6c46fcdccd87f' \
NGINX_IMAGE='codex/nginx-ui-security:nginx-1.30.6' \
./packaging/security/nginx-upgrade/build.sh
```

The example uses the existing local RepoDigest. On another host, first pull the
same digest from the production registry (10.43.11.54:5443/nginx-ui/security-fork)
and pass that registry reference as RUNTIME_BASE. Do not substitute a mutable tag.

The build runs with a 4 GiB memory/no-swap limit and 2 CPU quota. Sources and
compiler dependencies come from the inherited immutable Debian snapshot
(20261103T000000Z). Source package versions and every downloaded source archive
are locked, and extracted Debian module patches are retained. NGINX uses its
upstream tarball with a pinned SHA256. Its detached signature was independently
verified against nginx.org/keys/pluknet.key, fingerprint
D6786CE303D9A9022998DC6CC8464D549AF75C0A (Sergey Kandaurov).

All modules and the embedded Perl bridge are rebuilt with the NGINX binary.
The prior binary/module files are registered as local dpkg diversions. Debian
package metadata still describes the retained original packages; use `nginx -v`
and `/usr/local/share/nginx-ui-security/nginx-1.30.6/` for the actual runtime
version and checksums. Do not upgrade NGINX with apt inside a running container.
Future updates must rebuild this image and test module parity. Runtime Debian
libraries and application packages continue to be recorded in packages.lock.

Fixed SOURCE_DATE_EPOCH keeps RTMP's build-date fields deterministic. The
inherited date-time diagnostic is disabled because upstream NGINX uses -Werror;
all other compiler security/hardening flags remain enabled.

The builder explicitly checks exact module filename parity before image
creation; the final image validates module loading using nginx -t. Before
production rollout additionally test the actual configuration clone, Lua,
ModSecurity blocking/allowlists, njs, Perl, HTTP/stream and rollback. Rollback is
the previous immutable image digest; preserve its configuration/PVC snapshot.
