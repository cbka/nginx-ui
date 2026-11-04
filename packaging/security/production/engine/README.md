# Central CrowdSec engine

This directory provides the private control service (`control.py`), the fixed
CLI bridge used by the Security Center plugin (`client.py`), and the supervised
CrowdSec launcher (`start.py`). It is deployment machinery, not a public API.
This document describes code behavior and deployment requirements; it does not
claim that a production rollout or end-to-end enforcement test has passed.

## Architecture and access

Run one central engine with its own persistent configuration and data storage.
Nginx replicas use CrowdSec's LAPI for decisions; Security Center uses the
separate control service on port 8081 for management. The central configuration
is shared across these replicas, while enforcement remains an explicit policy
on each managed VHost. Installing or enabling the plugin alone must not opt
existing VHosts into enforcement. Existing foreign Lua hooks must remain intact;
conflicting target-VHost or inherited HTTP hooks require manual integration.

Expose control only as a private ClusterIP service. Restrict ingress with a
NetworkPolicy to the authorized controller pods. The Python listener uses plain
HTTP, so its bearer token does not provide transport encryption. Use an encrypted
transport if the cluster network cannot be trusted; never expose this listener
through a public ingress or public service.

Mount a private 64-character lowercase hexadecimal control token at
`/run/secrets/control-token`. Empty, missing, or malformed tokens fail closed.
The CLI bridge reads `SECURITY_CENTER_CONTROL_URL` and
`SECURITY_CENTER_CONTROL_TOKEN_FILE`; it refuses redirects and bypasses
HTTP proxy environment variables. Do not put tokens in command arguments,
images, repository files, or logs. Token rotation must update engine and clients.

The service accepts only fixed operations: list decisions/scenarios, add or
remove a validated decision, install/remove a validated hub scenario, reload,
and read/change sharing. Arguments are passed as an array, never through a shell.
Requests have an 8 KiB body limit; replies from CLI operations are capped at
2 MiB when read. The server serializes operations and uses socket timeouts.
Subprocess timeouts are finite; a client timeout is not evidence of rollback or
completion. Query current state before retrying a mutation.

## Sharing defaults

Seed `api.server.online_client.sharing` as the JSON boolean `false` in the
JSON-formatted `/etc/crowdsec/config.yaml`. Strings such as `"false"`, numbers,
and missing values are invalid. The launcher uses `-no-capi` while sharing is
false. Every validation run also uses `-no-capi`, including validation during
reload and rollback.

Only an authenticated explicit enable request may register missing CAPI
credentials and enable communication. Disabling sharing restarts the engine
with `-no-capi`; existing credentials may remain on disk without being used by
that process. Sharing means engine alerts, **not every blocked request**, and
must not be represented as a promise that an IP is added to a community list.
The control response's runtime check establishes a listening local engine and
matching recorded startup mode, not external receipt of alerts by CrowdSec.

## Cluster-wide events

Collect ModSecurity audit events and structured CrowdSec bouncer events on each
Nginx replica using the audit reader/normalizer under `packaging/security/`.
Resolve VHost identity from managed site policy metadata and the generated site
ID, not from untrusted request headers. Supply node identity as trusted collector
metadata. Ship the normalized events to central Loki, so load-balanced requests
can be queried across nodes and filtered by VHost, node, and source.

Configure the plugin's server-side `SECURITY_CENTER_LOKI_URL` and required Loki
credentials. `events_configured` means that the endpoint is configured, not that
collection or queries have been verified. The event API returns a bounded,
normalized projection rather than raw request bodies, headers, credentials, or
query strings. Keep raw audit logs private, with explicit retention and access
controls. Event-based rule/exception changes must use the normal managed policy
validation and transaction path; an event itself must never execute a rule change.

## Scenario transactions and recovery

The handler serializes writes. Before scenario install/remove, it snapshots the
entire configuration tree, including hub files and activation symlinks. It rejects
external configuration paths, escaping symlinks, special files, and snapshots
exceeding 20,000 entries or 64 MiB. Then it runs the allowed `cscli` operation,
validates with `-no-capi`, and restarts the engine. Command or restart failure
restores the configuration snapshot and attempts another validation/restart.

Keep `data_dir` outside the configuration tree. The live SQLite database is never
snapshotted or replaced by this transaction. Additional downloaded datasets may
remain as unused cache artifacts after rollback; restored configuration does not
activate newly installed scenarios. Do not perform concurrent out-of-band
configuration writes while a control operation runs.

This is a transaction with compensating rollback, **not crash-safe filesystem
atomicity**. A process/container crash during replacement needs operator recovery.
If rollback itself fails, the private `crowdsec-config-rollback-*` directory is
retained and its path is written to the engine error log. It can contain secrets:
preserve it securely, inspect configuration and runtime before further mutations,
and remove it only after recovery. Ensure its temporary storage survives long
enough for recovery; an ephemeral container filesystem is not a durable backup.
Successful operations and successful rollback remove their temporary snapshots.
Sharing updates similarly restore the previous configuration on reload failure;
a failed rollback must be treated as an unknown runtime state, not success.

## Verification before deployment

Run the focused tests without contacting devices or production services:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s packaging/security/production/engine -p 'test_*.py' -v
```

The unit tests cover the operation allowlist, fail-closed token authentication,
strict sharing booleans, `-no-capi` validation, and scenario/sharing rollback.
Deployment acceptance additionally requires private-network reachability checks,
sharing-off verification, a disposable VHost enforcement test, cross-node event
visibility, and a tested deployment rollback. These are separate checks and are
not established by unit-test success.


## Automatic installed Hub updates

The control service checks the official CrowdSec Hub hourly (`cscli hub update`,
then `cscli hub upgrade`, never `--force`). First check is delayed 60 seconds;
persistent last-attempt time prevents repeated downloads on control restarts.
The scheduler shares the control service mutation lock and also takes a process
file lock. Concurrent manual operations cause a retry on the next minute.

Only the existing activation set is retained. Previously disabled scenarios and
new collection dependencies are not activated automatically. Existing symlinks
continue to reference updated Hub files; existing regular active files retain
upgraded content. Local/tainted content is not force-overwritten. If the upgraded
collection requires a new disabled dependency, engine validation fails and the
configuration snapshot is restored. The engine reloads only when active rule or
lookup-dataset contents changed; Hub index-only refreshes do not reload it.
Dataset fingerprints exclude the live SQLite database and its journals.
Engine configuration (including community
sharing) must remain byte-identical. Lookup datasets have a separate bounded rollback snapshot, restored before the
recovery reload. Live SQLite database files and their journals are never
snapshotted or restored. An update failure with successful rollback retries after one hour.

Atomic status lives at `/var/lib/crowdsec/data/hub-update-status.json` and is
available via authenticated read-only `GET /hub-updates` on the private control
service. It includes success/failure, attempt/success times, Hub index SHA256 and
installed item versions. Configuration rollback failures are reported in engine
logs with the retained private recovery snapshot path. No automatic package or
CrowdSec binary upgrades are performed.

The production rollout deliberately changes `cscli.hub_branch` from the initial
commit pin to `master` in both the persisted configuration and the initialization
ConfigMap. Leaving the initial pin would only refresh that historical snapshot.
The scheduler does not change this configuration implicitly.

## AppSec virtual patching

Authenticated `GET /appsec` reports the official Hub catalog (`available`), installed
activation (`installed`), versions and status. `loaded: true` is reported only for
installed base-config/vpatch rules when both listeners are ready and a startup
receipt proves the current CrowdSec PID/start time/boot ID and unchanged rule and
configuration fingerprints. Other rules or unverified processes return `loaded: null`.
This proves engine loading, not that NGINX traffic used AppSec; the plugin reports
traffic integration separately.

Explicit deployment bootstrap `PUT /appsec {"enabled":true}` installs
`crowdsecurity/appsec-virtual-patching`, validates and restarts transactionally.
Allow up to 210 seconds for the initial download. No automatic activation happens
at image startup. `false` removes the two managed acquisition files; rules remain
installed for future use and hourly updates. CAPI settings are unchanged.

Private listeners (never publish externally):
- 7422: official `crowdsecurity/virtual-patching`, blocking response.
- 7423: managed detection configuration, same virtual-patching rules, with
  `CancelAlert()` and `CancelEvent()` to prevent downstream LAPI bans. It retains
  the internal rejection response as a match signal; NGINX **must not enforce**
  this response in detection mode, and must log it locally instead.

The bridge accepts `appsec status`, `appsec enable`, and `appsec disable` only.
Hourly upgrades retain genuinely new dependencies introduced by the official
virtual-patching collection, but never reactivate previously known disabled
entries or unrelated scenarios. Lookup data and configuration roll back together
on failed validation, without replacing live SQLite data.
