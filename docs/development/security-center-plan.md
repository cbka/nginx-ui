# Security Center fork integration

## Scope
User-authorized fork of nginx-ui, based on v2.9.4, with PR #1991 plugin system and CrowdSec/ModSecurity OWASP administration. No upstream pull request until requested later. No production rollout before integration verification.

## Acceptance criteria
1. Fork cbka/nginx-ui and dedicated feature branch; preserve original PR authorship and pin imported PR commit.
2. Integrate PR #1991 (head a12e4ff03f2212479d405168888f1dd127375944); resolve compatibility with v2.9.4 without removing recent security fixes. Plugin settings, authentication, certificates and logging tests pass.
3. Authenticated, interactive administrative Security Center shows available integrations, manages CrowdSec decisions and scenarios and validates ModSecurity mode/CRS settings/exclusions. Missing integration is explicit, never falsely reported as active.
4. No shell interpolation or client-controlled file paths. Secrets stay server-side. Invalid rules must not replace working configuration; reload failure restores previous config. Test validation, authorization, command failure and rollback.
5. Bounded, isolated runtime smoke proves Lua, ModSecurity and CRS load. CrowdSec engine lifecycle and shared configuration documented. No test resources left running.
6. Frontend lint, typecheck, focused tests; Go CI-equivalent race tests and production build. Record genuine external blockers and unverified portions.

## Work allocation
- Root: fork, PR integration, architecture, final verification and publication to fork only.
- Backend agent: bounded command adapters, safe WAF settings, HTTP authorization and focused tests.
- Frontend agent: responsive administration interface and tests.
- Runtime agent: image, module smoke and operator documentation.

## Progress
- SSH authentication verified for cbka; fork already exists.
- v2.9.4 cloned at 4049e42; Security Center implemented and integrated locally.
- PR #1991 is a draft; integration conflicts resolved locally. The external log analytics migration gap below remains a deployment blocker.

## User scope refinement: per-vhost policies
- Global ModSecurity settings are defaults; each explicitly managed site gets exactly one complete effective rules file. Do not load CRS at both HTTP and server level.
- Select existing Nginx UI site configurations; all server blocks within one site file share its policy and the UI must state this scope.
- Per-site mode and numeric settings may inherit or override defaults. Explicit local exclusions extend global exclusions; show effective values.
- CrowdSec decisions remain central; enforcement inherits global enablement or is explicitly enabled/disabled per site.
- Global changes regenerate affected managed sites transactionally; validate all and reload, restore all on failure.
- Preserve existing Lua and reject unsupported hook conflicts instead of overwriting them.
- Acceptance: two real virtual hosts show independent WAF/CrowdSec behavior, global defaults propagate to inherited sites, failed updates restore both files and prior configuration.

## Cluster event visibility and guided rule editing
- Central Loki view for both ModSecurity and CrowdSec across proxy nodes, filterable by trusted vhost identity and time range.
- Return normalized, bounded event summaries (rule/scenario, node, time, URI without query, parameter and action); never expose raw bodies, cookies, credentials or matched sensitive content.
- Vhost attribution must come from trusted per-site audit sources, not the client Host header. Unattributed CrowdSec events stay explicitly unattributed.
- Event actions prepare a reviewed vhost exception or a central CrowdSec decision. No event automatically changes security policy.
- Node rollout/collection completeness must be explicit; a local apply or a successful Loki query does not imply every peer is configured.

## Integration decisions and verification record
- Merge PR #1991 using its original history. The PR extracts the old embedded log
  indexer, GeoLite service and certificate config implementation. Release-added
  tests referring only to those removed implementations cannot remain host tests;
  remove orphaned files and preserve generic event-bus coverage using current events.
- The release stale-log cleanup fix has no equivalent verified in the external
  analytics plugin. This remains a production rollout blocker, detailed in the
  deployment guide; passing host tests does not close it.
- Site replication uses existing configured paired peers, signed requests, explicit
  controller ownership and monotonic revisions. Acknowledgements are per peer,
  never an atomic whole-cluster success claim. Global edits require synchronizing
  each affected site; a receiver never overwrites its unrelated global defaults.
- Event query results are merged chronologically across nodes before limiting.
  Node/pod identity comes from collector labels; vhost identity comes from managed
  site files rather than the HTTP Host header.
- Both ModSecurity matches and CrowdSec enforcement require a working collection
  pipeline on every serving node. The UI does not infer cluster completeness from
  a successful Loki query. The local preview uses explicitly labelled sample data.

## Verified on 2026-11-03
- Frontend: 548 tests / 1,386 assertions, full ESLint and Vue typecheck passed.
  Production build passed with bounded memory and two Less workers.
- Go: full race/coverage suite completed; the only failing package was cron,
  whose orphaned indexer references were then removed and whose targeted race/coverage
  rerun passed. All other packages passed the full run.
- Security Center targeted race tests include validation, rollback, replica
  ownership, stale/conflicting revisions, idempotence and global-default isolation.
- Independent read-only review found no concrete defect in event queries and signed
  site replication. Upstream node-auth verifies signed body/path/query/target and nonce.
- Runtime: 18 audit-reader/normalizer tests plus real Nginx request tests passed for
  scoped WAF behavior and CrowdSec enforcement attribution; timestamps preserved.
- Browser: actual Vue preview shows cluster CrowdSec events and node filter; demo
  exception draft flow checked. No production connection is implied.
- Actual `Service.ApplyWAF`/`Service.ApplySite` output loaded by real Nginx passed
  request tests: per-site exclusions, scoped parameter exceptions, exact path
  blocking, CRS enforcement and CrowdSec enable/bypass. This verifies generated
  configuration syntax beyond tests that use a fake command runner.

## Reusable security templates (user scope extension)
- Built-in Exchange on-premises and GitLab baselines plus named custom templates.
- Templates hold structured SitePolicy snapshots, not raw Nginx directives. Existing
  upstream proxy/config templates remain separate.
- Loading a template creates a reviewable local form draft. Only the existing
  validated ApplySite operation changes a site; peer sync stays explicit.
- Preview changes before applying; copying or updating a template never changes
  previously configured sites. Built-ins are immutable; custom templates can be
  saved/deleted and preserve all settings accepted by normal policy validation.
- Acceptance: safe bounded CRUD and authorization tests, custom policy round trip,
  draft-only UI and before/after changes, rebuilt production/preview bundles and image.

### Template verification
- Final frontend suite: 550 tests / 1,397 assertions passed, full lint and typecheck
  passed; production and demonstration bundles rebuilt.
- Backend race tests cover custom policy round trips, immutable built-ins, malformed
  and oversized input/storage, authorization and 20 concurrent saves without lost
  updates. Template operations do not invoke Nginx or alter applied website policies.
- Browser preview verified selecting GitLab, reviewing the policy differences and
  copying only to an unsaved website draft.

## Global CrowdSec community sharing (user scope extension)
- Manage the real engine `api.server.online_client.sharing` setting, independently
  of site enforcement, local logs, blocklist pulling and other telemetry settings.
- Unknown integration/defaults must remain unknown; the new operator example is
  explicitly off. Existing `.local` overlays take precedence and retain unrelated
  configuration and credential references.
- Acceptance: privileged API, bounded unambiguous YAML, fixed validation/reload
  hooks, rollback on failure, explicit metadata notice before enabling, no automatic
  external reporting and no claim that saved configuration verifies live delivery.
- Verification: backend race/auth/rollback tests pass; frontend 552 tests / 1,408
  assertions, full lint and typecheck pass. Browser demo starts off and shows the
  metadata/destination confirmation; cancelled and reset without activation.
- Official CrowdSec 1.8.2 validation tested offline with network disabled for both
  values, overlay precedence, preserved credentials/pull settings and invalid input.
