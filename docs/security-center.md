# Security Center: deployment and operational boundaries

This fork adds a separately signed Security Center plugin; it does not automatically enable
protection on existing proxies. There is no production deployment in this change.

## Runtime layout

`packaging/security/Dockerfile` packages the **fork's compiled binary**, Debian
Nginx, Lua, ModSecurity v3 connector, Debian OWASP CRS, the CrowdSec Lua bouncer
and `cscli`. It does not apply patches to another binary. Build frontend assets
and the Go binary using the repository release procedure first; place the resulting
Linux amd64 binary at `packaging/security/artifacts/nginx-ui` (gitignored).

The build helper stages an explicit allowlist of runtime files; local state and signing keys never enter its context. Supply `DEBIAN_BASE` as a verified
`debian:trixie-slim@sha256:…` image digest and `DEBIAN_SNAPSHOT` as a verified Debian
snapshot timestamp. Both are deliberately required: no floating base or silently
moving apt repository is presented as reproducible. Record these inputs, the fork
commit, binary SHA256 and resulting image digest with every release. The image
records installed package versions in
`/usr/local/share/nginx-ui-security/packages.lock`.

The current recipe supports **amd64 only**, because the verified upstream cscli
release artifact contains an amd64 static binary. Other architectures must use
separately verified artifacts or a source build.

Verified upstream inputs:

- CrowdSec Nginx bouncer v1.2.3, official release tarball, SHA256
  `8cb0c176f01bda3a5fc5493d20bcd7261630c7dfbd60c00b2bff8eefc8fe84d5`.
- CrowdSec v1.8.2 official release tarball (only cscli extracted), SHA256
  `6e0b2add0ff3231dca3db7146834d7fea028215b915e2da39ebe30fc9f11436f`.
- lua-resty-http v0.17.2 upstream archive, SHA256
  `3da18ca8582243eff28302591e36651dc7fab046e77336aa4a6fa718bccce4a2`.

Checksums pin bytes retrieved from upstream; they are not an independent publisher
signature. Package names and CRS paths were checked against Debian trixie package
metadata. Debian's maintained CRS package is 3.3.x, **not the newest upstream CRS
major**. Upgrading CRS major requires a separate rule compatibility test.

## Startup and existing state

Mount initialized state at `/usr/local/etc/nginx-ui`, including `app.ini` and the
existing database. Entrypoint fails if `app.ini` is missing and never initializes,
rewrites or copies over a mounted Nginx configuration. Nginx must pass `nginx -t`
before supervisor starts. Configure Nginx UI's restart command as
`/usr/local/sbin/restart.sh`; this validates before restarting Nginx.

Keep image update ownership with the deployment controller. The official upstream
image updater must **not** replace this security image with plain upstream Nginx UI.
The source fork must enforce this operationally before rollout; an environment
variable alone does not establish that protection.

## ModSecurity wiring

The global default policy lives at `/etc/nginx/plugins-persistent/io.github.mctdatapool.security-center/modsecurity.conf`.
Per-site management renders a complete effective policy for each managed server,
including explicit overrides/exclusions and that site's audit path. **Do not include
this full policy at `http {}` when using per-site policy files**: the Nginx connector
merges parent and child rules, and duplicate rule IDs fail validation. Security
Center rejects parent full rulesets for both global and site saves. The legacy
`loader.conf` is a standalone configuration reference, not an activation recipe
for Security Center; remove it from the parent context before management. Saving
global defaults alone does not enforce anything until managed sites are applied.

Per-site CrowdSec enforcement uses `set $nginx_ui_crowdsec_enabled 0|1` and
`access_by_lua_file /usr/local/lua/nginx-ui/security-access.lua` in the managed server.
Include `/usr/local/share/nginx-ui-security/crowdsec-init.conf` once in `http {}` for
bouncer initialization. The controller must refuse conflicting existing Lua access
hooks (including locations/includes) rather than silently replacing authentication.
Central decisions remain shared; bypassing a site's enforcement does not delete a
central decision.

The policy includes:

1. `/etc/modsecurity/modsecurity.conf` for body processing and audit settings;
2. `/etc/modsecurity/crs/crs-setup.conf` for CRS defaults;
3. configured CRS threshold/paranoia settings;
4. `/usr/share/modsecurity-crs/rules/*.conf`;
5. reviewed rule exclusions.

The runtime supplies a minimal base file; the web controller owns the generated
policy. Begin in DetectionOnly, inspect false positives, and enable blocking after
site checks. Audit logs can contain request bodies and personal data: restrict log
access and retention. Rule exclusions weaken protection and require review.

## CrowdSec wiring

Run the CrowdSec engine/LAPI separately. Its acquisition configuration must consume
logs from all proxy peers with trusted client-IP handling. Each peer's Lua bouncer
gets its own server-side bouncer credential and uses the same LAPI decision set.
The bouncer credential is distinct from cscli machine credentials.

The image installs bouncer Lua code but intentionally does **not** include its hooks
in live Nginx configuration. Examples are under
`/usr/local/share/nginx-ui-security/`. Provision
`/etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf` as a Secret, substitute the actual
LAPI address and bouncer key, and merge the example hooks with existing Lua hooks.
Do not add a second conflicting `access_by_lua_block`; location-level Lua hooks may
also override inherited hooks. Verify enforcement on each served location.

Keep CrowdSec AppSec disabled when ModSecurity is the chosen request WAF, unless a
separate design explicitly justifies running both.

`cscli` reads server-side `/etc/crowdsec/config.yaml` and machine credentials.
Remote LAPI permits decision operations; changing scenarios affects local engine
configuration and requires an engine reload. A separate engine therefore needs a
properly scoped control integration/shared configuration plus an explicit reload
hook before scenario changes can be enabled. Merely installing cscli beside Nginx
UI does not remotely administer scenarios. Do not mount a Docker socket or grant
unrestricted cluster execution to bypass this boundary.

## HA and acceptance before rollout

This initial runtime is **not** a drop-in replacement for the existing cluster
image: it packages Lua, ModSecurity and stream support, not every historic dynamic
module. Compare every live directive/module, state path and reload mechanism.
Security policy files and bouncer credentials need explicit per-peer distribution;
normal site synchronization must not be assumed to synchronize these files.
A UI success on one instance alone is not proof that three peers enforce the rule.

Required acceptance:

- Build-time `smoke.sh` passes module loading, CRS parsing and
  cscli execution. This is a syntax check, not Lua initialization or request-blocking proof.
- Authenticated admin API tests reject unprivileged users, invalid inputs and
  arbitrary command/config injection; failed apply restores previous policy.
- An isolated proxy serves a normal request, detects/blocks a controlled WAF test,
  enforces a temporary CrowdSec decision, and restores access after removal.
- Existing Lua authentication, certificates, TCP/UDP routes, reload and all three
  peers are verified before any production rollout.
- Pin the resulting image digest, retain previous image/config and perform a
  staged rollout. No production rollout or upstream PR is included here.

## Official references

- https://nginxui.com/guide/config-nginx
- https://docs.crowdsec.net/u/bouncers/nginx/
- https://github.com/crowdsecurity/cs-nginx-bouncer/releases/tag/v1.2.3
- https://github.com/crowdsecurity/crowdsec/releases/tag/v1.8.2
- https://packages.debian.org/trixie/libnginx-mod-http-lua
- https://packages.debian.org/trixie/libnginx-mod-http-modsecurity
- https://packages.debian.org/trixie/modsecurity-crs
- https://packages.debian.org/trixie/all/modsecurity-crs/filelist

## PR #1991 plugin runtime

The integrated plugin system defaults its storage to the directory next to app.ini:
`/usr/local/etc/nginx-ui/plugins`. Persist that directory with application state.
Server plugins run as child executables with Nginx UI's OS privileges; signatures
and capability permissions are not an OS sandbox. This runtime executes Nginx UI
as root to retain existing Nginx management behavior, so install only trusted
plugins and keep developer mode disabled.

PR #1991 falls back to running without per-plugin resource limits if its cgroup v2
subtree cannot be created. Ordinary container cgroup mounts are often read-only.
Always enforce hard limits for the entire container; do not grant a privileged
container/host-wide cgroup access merely to enable optional per-plugin accounting.
Verify plugin processes stop with their supervisor and survive application reloads.

DNS and log capabilities moved into separate official plugins must be installed,
version-pinned and tested before production. Merely merging the plugin host does
not package those capabilities or prove certificate issuance and log views work.

### Known log analytics migration gap (release blocker)

Host fix [#2070](https://github.com/0xJacky/nginx-ui/pull/2070), commit
`0c5fec967a593006273b3cf0d5598b78fcca1dd8`, removes stale log index entries when both
the site declaration and main log file are gone. PR #1991 moves this responsibility
out of the host. The public `nginxui/plugin-log-analytics` HEAD inspected on
2026-11-03 (`cab5b25`, 2026-10-30) still adds every persisted index path in
`internal/indexer/log_file_manager.go:GetAllLogsWithIndexGrouped`; the host's stale
predicate and sweep are absent. The official catalog advertises plugin 1.0.0 dated
2026-10-04, which also predates #2070. Consequently, preserving this fix is **not
verified** and deleted-site logs may reappear after plugin migration. Port and test
the cleanup in the extracted plugin before deploying it as a replacement. This
repository has not modified or published that separate plugin.

## Runtime verification performed

On 2026-11-03, an isolated image was built from the documented digest and snapshot.
Installed Nginx `1.26.3-3+deb13u10`, Lua module `1:0.10.28-2`, ModSecurity connector
`1.0.3-2+b2`, CRS `3.3.7-1+deb13u2` and cscli `v1.8.2-3d369d64` were confirmed.
The request test used the initial managed policy (IDs 900110/900120) with blocking
mode enabled. It returned normal **200**, XSS **403** (CRS rule 949110), mocked LAPI
ban **403**, and restored **200** after removing the decision. A missing
`resty.string` dependency was found by actually starting Nginx and fixed with the
pinned upstream v0.16 archive, SHA256
`77f006a97fd4a3be4a82dcf2d5f1482e399b70fb35454c5b5ad4b97ff1dded0d`.

This runtime-only test used the official v2.9.4 application binary as a placeholder;
it does **not** verify the fork's application/plugin binary. The placeholder was
removed after the test so it cannot accidentally ship. Containers used a hard
512 MiB limit, no swap and no external networking. Temporary containers and the
test image tag were removed; build cache layers remain for the final fork build.

A second runtime verification added the body-processing baseline from the
[official ModSecurity 3.0.14 recommended configuration](https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.14/modsecurity.conf-recommended):
explicit JSON, `+json` and XML parsers; argument/depth limits; malformed-body,
multipart and internal-error checks. Baseline IDs 200000–200009 are separate from
CRS exclusions. Verified real requests: valid JSON/XML **200**, Unicode-escaped XSS
in JSON and `application/problem+json` **403**, malformed JSON/XML **400** via
baseline rule 200002. Query XSS and mocked CrowdSec ban/unban tests also still pass.
These rejection checks follow SecRuleEngine mode: DetectionOnly logs instead of
blocking, and Off disables inspection. No production traffic was used.

## Per-vhost runtime checks

`packaging/security/vhost-smoke.sh` runs two real Nginx virtual hosts against a local
mock LAPI. Verified: an exclusion on B leaves A blocked; a scoped argument exception
only matches B's exact `/search` path; an exact `/private` block also blocks query
variants but not `/private-more`; a global mode change affects the default policy
without changing B's override; a shared CrowdSec decision blocks A while B explicitly
bypasses enforcement. A parent full ruleset plus child full ruleset fails `nginx -t`
with duplicate rule IDs. Tests also verify distinct site audit files without HTTP
headers or bodies. CRS dynamically adds audit section E, so baseline rule 200009
removes sensitive sections again in logging phase before serialization.

Primary inheritance references:
https://github.com/owasp-modsecurity/ModSecurity-nginx/blob/v1.0.3/src/ngx_http_modsecurity_module.c
(`ngx_http_modsecurity_merge_conf` calls `msc_rules_merge`), and
https://github.com/openresty/lua-nginx-module#access_by_lua_block.

## Shared audit events across peers

The runtime includes the supervised Python `security-audit-reader` process, disabled
by default. Enable `NGINX_UI_SECURITY_AUDIT_ENABLED=true` and inject `NODE_NAME` from
the Kubernetes downward API on **each** serving peer. The reader consumes
`/var/log/nginx/modsecurity/<sha256(site-name)>.json` and the fixed Nginx
`/var/log/nginx/error.log`, including uncompressed numeric rotations. Ordinary error
lines are skipped; only structured events emitted by the pinned CrowdSec wrapper qualify.
It resolves the site name from the matching server-owned
`/etc/nginx/plugins-persistent/io.github.mctdatapool.security-center/sites/<hash>.json` and validates the hash. HTTP Host
headers never determine security-event attribution.

Persist `/usr/local/etc/nginx-ui/security-audit-state` per instance. It contains a
single-owner process lock and atomic, fsynced inode/offset checkpoints. The reader
polls once per second, limits sources to 256 files, records to 1 MiB, and work to
8 MiB per cycle. It handles rename rotation, truncation, incomplete records and
restart. Output becomes durable before the checkpoint; a crash can replay an event
with the same stable `event_id`, which consumers must deduplicate. A partially
written output tail is repaired before replay. Missing site metadata holds the
source for later rather than inventing a vhost. Never share one cursor file across
multiple nodes.

Normalized output is `/var/log/nginx/security-events.jsonl`. Merge the supplied
`security-events.alloy.example` into each existing collector and mount the same log
volume read-only there. This sends `job="nginx-security"` to the existing shared
Loki writer, with trusted node/pod/namespace labels. The API reads all matching peer
streams; no sticky browser session or selected serving node is required. Do not
label Loki streams by request ID, IP, or URI. Enable retention/rotation using the
reviewed `security-events.logrotate.example`; raw audit rotations are short lived
and remain local. Raw rule match text can contain sensitive values even with body
sections removed, so **never ship raw audit lines**.

The normalizer emits rule ID, method, query-free path, parameter name, client IP,
transaction ID, action and a safe rule explanation. It deliberately omits raw
headers, bodies, query values, matched data and free-form messages containing
request interpolation. Unknown rules get an ID-based explanation. Paths and client
IPs themselves can be sensitive; apply the intended access control/retention.

Live read-only inspection on 2026-11-03 confirmed Alloy v1.21.2 native sidecars on
all three nginx-peer pods and the leader. They currently collect only `access.log`
and `error.log`; **the security source is not installed in production**. Existing
Loki retention/lookback is 336 hours (14 days), query limit 5,000, endpoint
`http://nginx-loki.nginx-logging.svc.cluster.local:3100`. Existing plain logs use
`job="nginx"`, so they do not populate the new security-event view automatically.

CrowdSec events come from wrappers around the pinned bouncer's actual ban/captcha/
challenge remediation functions, before those functions terminate or redirect the
request. An application-generated 403 is not a CrowdSec event. The server-generated
`$nginx_ui_security_site_id` is resolved against the same trusted site metadata used
for ModSecurity. Bypassed vhosts emit no enforcement events. Missing site identity
suppresses attributed logging but does not bypass enforcement. These local events
have no scenario name because the bouncer does not provide one; central engine
alerts/scenario records remain a separate, currently unconfigured feed.

Both event sources preserve their original event time. ModSecurity's zone-free
legacy timestamps are interpreted as UTC, matching the image's explicit `TZ=UTC`;
do not override that setting without changing the parser. The Lua emitter writes
UTC explicitly. Alloy parses `event_time`, so replay does not make historical events
look newly generated. Loki's age limits may reject very old backfill; do not falsify
event times to bypass those limits. Existing plain error-log collection may retain
request details independently; the new sanitized security stream does not change
that existing collection policy.

Validation: Python tests cover redaction, trusted attribution, stable event IDs,
malformed input, restart, rename rotation, truncation, partial input/output recovery,
and symlink/unrelated-file rejection. Runtime request tests cover policy
isolation, an actual CrowdSec ban attributed only to the enforced vhost, no false
event for an application 403 or bypassed vhost, preserved timestamps, and restart
without duplicate output. Production collection and shared API queries still need
an end-to-end deployment check before rollout is considered complete.

The opt-in Go test `TestGenerateRuntimeFixtures` also generates policies and Nginx
snippets through the actual `Service.ApplyWAF`/`Service.ApplySite` paths. The
`generated-policy-smoke.sh` acceptance script loads these unmodified outputs in
real Nginx and verifies scoped exceptions, rule exclusions, exact path blocking,
CRS attacks and per-site CrowdSec enforcement. The generation test mocks command
execution only; the subsequent runtime test performs the real configuration and
request checks.

### Local integrated build verification (2026-11-03)

A deliberately retained local build artifact is `codex/nginx-ui-security:fork-20261103`,
image ID `sha256:9c02388832a8f27beeb001c9571617cfd0b52abb58707d00031415aff7872ee8`.
It contains the actual fork binary with embedded frontend (binary SHA256
`ea04480c9fb310c24a03a116cc97755747bc3586a7886cc2a520f1314f40d522`).
This is a local review/test artifact deployed only in the isolated local lab,
not published or deployed to production.

The template- and community-control-inclusive final image passed supervisor startup, embedded homepage
delivery, anonymous security, template and sharing API rejection (403), and exact SHA256
verification of the served SecurityCenter frontend asset including template and community-reporting UI.
The unchanged runtime previously passed real service-generated policy tests, JSON/XML
200/403/400 request checks, per-vhost CrowdSec event attribution and timestamp checks,
and 18 Python normalization/cursor tests. Temporary smoke-test containers and obsolete unused image tags
were removed; no temporary smoke-test volumes or networks remain. The persistent
local lab and its networks remain intentionally available. The image and ignored compiled
binary remain intentionally available for review. Deployment prerequisites and
external-plugin limitations above still apply.

## CrowdSec community reporting: separate engine integration

The switch controls the engine's `api.server.online_client.sharing` boolean. It is
not a bouncer flag, local decision switch, or a switch for downloading blocklists.
CrowdSec 1.8.2 defaults an omitted sharing value to **true** in
[its API configuration loader](https://github.com/crowdsecurity/crowdsec/blob/v1.8.2/pkg/csconfig/api.go).
The [signal sender](https://github.com/crowdsecurity/crowdsec/blob/v1.8.2/pkg/apiserver/apic.go)
checks this flag before sharing alerts. Explicitly merge the supplied
`engine-adapter/sharing-off.yaml.example` into the actual engine configuration before
starting a new engine if reporting should initially be disabled. This fork image
contains only cscli and the bouncer, so placing that file inside the Nginx container
without connecting it to the engine does **not** disable reporting.

The upstream loader merges `config.yaml.local` over `config.yaml`. Security Center
must point at the base path and preserve/update the effective existing overlay.
Never validate an overlay as if it were a complete base configuration. Environment
substitution or other external configuration generation must not later override the
managed value. Keep engine credentials and kubeconfig server-side and out of API
responses, logs and browser state.

`engine-adapter/validate-kubernetes.sh.example` and `reload-kubernetes.sh.example`
are fixed-target operator adapters for a separately deployed engine. They are not
installed or invoked automatically: review namespace, deployment, container, binary
paths, readiness and least-privilege kubeconfig first. The engine and UI must mount
the **same persisted configuration** at their configured paths; a read-only
ConfigMap/subPath copy is unsuitable for this write-and-reload contract. Configure
one management writer, not independent competing copies. The validation hook runs
the real engine's `-c /etc/crowdsec/config.yaml -t`; the reload hook restarts only that
fixed deployment and waits for readiness. Its timeout must fit the backend command
budget. A hook failure rolls back the file and requires recovery reload; successful
commands alone do not prove that the remote running engine is using the new flag.
The API therefore distinguishes saved configuration from runtime verification.

Offline verification uses `sharing-engine-smoke.sh` with the official 1.8.2 engine
binary from the same SHA256-verified release archive used for cscli, mounted as
`/engine`, in a `--network none --memory=256m --memory-swap=256m` disposable container.
Actual engine validation passes both booleans, the `.local` override wins while base
credentials remain, explicit pull settings remain unchanged, and an invalid boolean
is rejected. No external reports can leave that container. `cscli config show` shows
the merged input before engine defaults; omitted sharing appears null there, while
the engine loader's documented source sets its default to true.

The final partial-error UI correction is deployed to all three local lab nodes,
with their existing accounts and policy state preserved. Each node serves the
final SecurityCenter asset with SHA256
`e8358b11540bb841804068db26237fb5bbdd80d7fa1bb59533aafd633826e0cf`
and still accepts normal requests (200) while blocking the XSS test (403).
The lab engine and gateway intentionally retain their earlier runtime image
`sha256:937c25758cc4b6bd752a13b53975c693732c3fd7ec6ab069538546b36e21fdbc`;
they do not execute the UI binary and remain active consumers, so that image must
not be deleted as unused.

The image build stages an explicit allowlist of Dockerfile inputs only. A
regression test invokes the real staging script with a fake Docker client and
readable dummy lab credentials, checks the exact COPY input set, and verifies
staging cleanup. Local cluster state, databases, credentials and logs never enter
the build context.

## Plugin lifecycle

Build and install the signed package separately from the host image; see
[plugin documentation](../plugins/security-center/README.md). Security routes are
owned by the plugin and disappear when disabled. Explicit disable validates and
reloads Nginx after removing managed site hooks; it retains desired configuration
for re-enable. This action applies to the selected node. Other nodes must be
disabled separately. A crash or host restart does not implicitly remove protection.
