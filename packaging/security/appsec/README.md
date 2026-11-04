# CrowdSec AppSec in the Security Center

Security Center 0.3 adds official CrowdSec virtual patches alongside existing
ModSecurity CRS and CrowdSec IP decisions. The central engine installs
`crowdsecurity/appsec-virtual-patching` explicitly, transactionally. The hourly
Hub update adopts newly published dependencies of that collection without
reactivating previously known disabled entries. Community sharing is unchanged.

## Modes and scope

Global `appsec_mode` and site `appsec` support `off`, `detection`, `block`;
site additionally supports `inherit`. Absent legacy fields resolve to off.
Saved templates and signed site replication carry these fields. Existing
unmanaged sites do not gain hooks automatically. AppSec can operate while a
site's ModSecurity and IP-bouncer modes are off. Plugin deactivation detaches
all managed security hooks, retaining desired configuration for reactivation.

CrowdSec IP/CIDR allowlists apply to both IP remediation and AppSec. They do not
remove existing central decisions or suppress unrelated log-based scenarios.

The private central engine exposes block port7422 and detection port7423.
Detection has the same base/virtual-patch rules, but CancelAlert/CancelEvent hooks
prevent detection traffic from feeding LAPI alerts or automatic IP bans.
NGINX records a local detected event; its client response remains unchanged.
Only the explicitly blocking mode returns403 for a positive AppSec result.

## Runtime configuration

Build the overlay Dockerfile using an immutable verified production base and an
allowlisted context containing security-access.lua, nginx_ui_appsec.lua,
crowdsec-init.conf and audit_normalizer.py. Supply the private fixed-endpoint
configuration and raw key as read-only Kubernetes Secret items under
`/etc/crowdsec/bouncers/`; see ../appsec-runtime.md. Master initialization reads
the private key before workers drop privileges. Keep the official bouncer's
APPSEC_URL empty: the site hook selects the correct listener and disables the
official combined AppSec call to avoid duplicate enforcement.

Publish7422/7423 only on the private ClusterIP service and allow only existing
fork proxy/leader pods through the engine NetworkPolicy. PublicService/DNAT
ports do not change. Control API authentication protects engine inventory and
bootstrap. The plugin exposes only read-only inventory; mode changes use the
existing validated policy transactions.

## Status and limits

Available is catalog presence; installed means enabled Hub files. Loaded is
confirmed only when an atomic startup receipt matches the live CrowdSec PID,
process start time, kernel boot and unchanged relevant configuration/rules,
and both listeners are ready. Stale/unavailable proof is unknown, never green.
Configured local site counts do not prove traffic coverage. Disabled NGINX
sites can retain desired policies. End-to-end probes establish actual behavior.

The initial failure policy is passthrough with explicit error events: AppSec
unavailability does not take hosted services offline. Inspection is bounded to
10MiB request bodies,200 headers and short network timeouts. Existing request
and body limits remain in effect. File-spooled bodies stream in64KiB chunks;
raw headers/body/query secrets are not written to the shared security feed.

## Rollback

Before deployment retain immutable proxy/engine images, signed plugin0.2 and
backups of workload templates, service, NetworkPolicy, credentials and policy
state. Set AppSec off and synchronize managed sites before restoring old runtime
images. Disable managed AppSec acquisitions via authenticated control API, then
restore the previous engine image. Restore workload/secret/network additions
from backups only after their current consumers have stopped. Never restore an
old CrowdSec SQLite database over current decisions. Validate NGINX and readiness
one peer at a time; public service selection and addresses remain unchanged.

## Verification

Go policy/API tests cover legacy-off, validation, independent modes, signed
replication and plugin deactivation. Engine tests cover transactional rollback,
foreign-file rejection, pair repair, updates and startup-receipt invalidation.
Real CrowdSec1.8.2 + NGINX tests prove malicious detection200/no LAPI alerts or
bans, block403, benign200, off/allowlist bypass and file-spooledPOST inspection.
