# Security Center plugin extraction

## Objective
Move security management into an independently packaged, signed plugin, using
PR #1991's native process and webapp integration. Explicit disable turns off
ModSecurity and CrowdSec enforcement while retaining configured policies for
reactivation. This supersedes the earlier preserve-enforcement-on-disable proposal.

## Work allocation
- Backend: plugin-owned policy, events, templates, CrowdSec and HTTP implementation.
- Frontend: plugin-owned routes, views, API adapter and webapp bundle.
- Host/runtime: generic authenticated host bridges and transactional lifecycle.
- Integration: signing/packaging, isolated lab migration, serial bounded tests,
  browser acceptance, review and cleanup.

## Acceptance criteria
1. A signed local package installs through the ordinary plugin API with developer
   mode disabled. Security routes and navigation are registered by the plugin.
2. Anonymous, API-token-only, expired secure-session and unsafe remote mutation
   paths cannot bypass the existing protection for administrative changes.
3. Global and per-vhost policies, templates, central events and explicit peer
   synchronization work on the three-node lab.
4. Explicit disable removes both WAF and CrowdSec enforcement through validated
   Nginx changes. Failed validation/reload cannot report a successful disable.
5. Policy settings survive disable and are restored on enable. A process crash is
   not an explicit disable request. Unreachable peers are not reported as off.
6. Real request checks demonstrate WAF and CrowdSec on/off/on, and normal HTTP
   traffic remains available. No test bans or automatic load remain afterward.
7. Tests/builds run serially under hard resource limits; only the persistent lab
   and required plugin artifacts remain. No production resources are modified.

## Execution order
Implement independent components; reconcile host/plugin contracts; run focused
regressions; build host and signed plugin; install on the isolated lab; verify
lifecycle and browser flows; review changes and publish fork commits.

## Status
Implemented and accepted on the isolated three-node lab on 2026-11-03.

- Signed community package v0.1.0 installed through the regular plugin API on
  all three nodes, developer mode disabled; plugin status running without error.
- Host frontend: 554 tests / 1,422 assertions, type checking and production build
  passed. Plugin frontend lint/type checking/build and bundle registration,
  teardown and reactivation tests passed. Additional lifecycle confirmation tests
  passed after the UI wording change.
- Focused Go tests passed for plugin API/domain/native process, host activation,
  deactivation, transactional rollback/CAS/symlink rejection, privileged HTTP
  authentication, credential stripping and authenticated peer replication.
- Python audit/packaging tests passed. No unbounded Node builds were used.
- Real requests on node1/node2/node3: normal traffic 200; WAF path block 403;
  temporary CrowdSec decision blocks normal traffic with 403. Explicit disable
  on each node changes both to 200. Enable restores CrowdSec 403; after removing
  the temporary decision, normal traffic is 200 and WAF path blocking is 403.
  Policies, ownership and revisions are unchanged. Reproduction:
  `python3 packaging/security/local-cluster/verify-plugin.py`.
- Peer synchronization confirms the saved revision independently on node2/node3.
- Browser acceptance confirmed plugin navigation, OTP reauthentication, global
  settings, per-vhost policies, reusable template controls, and central Loki
  events from all three nodes for both WAF and CrowdSec.

## Scope and retained lab resources
Explicit disable is confirmed on the selected node, not an implied atomic
cluster shutdown. Disable each node when stopping protection cluster-wide.
The plugin does not stop an independently managed, shared CrowdSec engine.
The isolated lab intentionally has no community reporting, its engine config
is read-only, and no scenario reload adapter is configured; the UI explains
these unavailable operations. The external marketplace is unreachable from
the isolated network; this does not prevent signed local package installation.

The eight named lab containers (three nodes, CrowdSec, Loki, Alloy, Faker and
gateway), their state and networks remain deliberately available for user
testing. The Faker is stopped, test bans were removed, and temporary build/test
containers were removed. Signing keys remain in ignored private local state;
only the public signer and signed package are distributable. Production was
not modified.
