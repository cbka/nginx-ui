# Security Center plugin

A resident native Nginx UI plugin providing the full Security Center webapp and
backend: per-site ModSecurity/OWASP CRS policies and exceptions, CrowdSec
management and signal-sharing configuration, reusable policy templates,
cluster event views, and signed peer policy synchronization.

The host contains generic authenticated plugin transport and bounded Nginx file
transactions. Security policy validation, rendering, persistence, APIs, migration
and lifecycle handling run in this plugin process, not core Security Center routes.
The executable currently builds in the fork's Go module and reuses its generic
JSON-RPC protocol transport. No core security service is called.

## Build

From the repository root, build `./plugins/security-center` to
`plugins/security-center/server/security-center`. Build the Vue contribution with
`plugins/security-center/webapp/build.sh`. Package/sign with the repository's
security plugin packaging script. The manifest describes the actual assets.

## Operator configuration

The process uses server-owned `SECURITY_CENTER_*` environment settings (the same
suffixes as the former built-in settings). These are not editable browser paths
or command arguments. Enable `ENABLED`, `MODSECURITY_ENABLED`, and optionally
`CROWDSEC_ENABLED`; configure `CSCLI_PATH`, `NGINX_PATH`, `BASE_CONFIG`, `CRS_SETUP`,
`CRS_RULES`, optional `CROWDSEC_RELOAD_PATH`, `SHARING_CONFIG_PATH`,
`SHARING_VALIDATE_PATH`, `LOKI_URL` and `LOKI_TOKEN_FILE` as appropriate.
Managed storage is assigned by the host under
`/etc/nginx/plugins-persistent/io.github.mctdatapool.security-center`.

The first start adopts marked legacy `/etc/nginx/security-center` policies and
custom templates, preserving owner/revision metadata. Copied policy files and
site include replacement commit together with Nginx validation and reload;
legacy source files remain as an inert backup. Unowned or conflicting Nginx
security directives are rejected rather than overwritten.

## Disable and re-enable

Explicit disable/uninstall first removes every owned local site enforcement
include in one host transaction, validates and reloads Nginx. A failed transaction
prevents successful deactivation. Desired policies and templates remain stored;
re-enabling restores them. Global Lua initialization may remain loaded, but the
removed per-site access hook performs no enforcement. Existing CrowdSec decisions
are not deleted from the independent engine.

Lifecycle is **per node**. Disabling the controller plugin does not disable an
independently enabled peer. Disable each node when intending a cluster-wide stop.
A process crash or host shutdown does not silently remove protection; explicit
lifecycle actions and failure handling are separate.

Native plugins are trusted installed programs, not an OS sandbox. Installation
must approve privileged HTTP, lifecycle, Nginx transaction, site inventory and
paired cluster synchronization permissions. All HTTP calls still require an
interactive user and the host's verified secure session; the Unix socket also
requires a per-process secret. Peer changes arrive only through the host's
verified paired-node RPC context. Reload acknowledgements do not imply that
unrelated peers applied the same configuration.

## Supported platforms

The current signed package targets Linux amd64 and requires this fork's generic
privileged HTTP, transaction and lifecycle extensions. The paired runtime provides
Nginx, ModSecurity/OWASP CRS, Lua and cscli. Other platforms are not packaged yet.

### Activation and settings

The host plugin switch is authoritative for management availability. The legacy
`SECURITY_CENTER_ENABLED` flag does not need to be set for this resident plugin.
Engine flags (`SECURITY_CENTER_MODSECURITY_ENABLED` and
`SECURITY_CENTER_CROWDSEC_ENABLED`) still describe operator-provisioned integrations;
the plugin switch does not provision either engine or configure a website.
The plugin settings drawer links to Security Center. Missing engines and central
logging are shown explicitly instead of issuing requests to disabled APIs.
`events_configured` only indicates a configured Loki endpoint, not reachability
or proof that events are being collected.

### Source IP exceptions

Security Center provides separate ModSecurity and CrowdSec IP/CIDR lists in
Global defaults and each website policy. Global and website entries are additive;
a website cannot negate a global exception. Up to 400 effective entries per
engine are accepted. IPv4/IPv6 addresses and networks are validated server-side.
Empty lists preserve the existing protection.

ModSecurity exceptions bypass the entire inspection for that request, including
custom path blocks. CrowdSec exceptions bypass the local Nginx bouncer only;
they do not delete central decisions, stop detection, or change community sharing.
Both use Nginx's resolved client address, never a request-supplied forwarding
header. If a NAT or proxy address represents many visitors, exempting it also
exempts those visitors. Public source IPs must first be preserved or established
through explicitly trusted proxy configuration.

The CrowdSec feature requires the matching runtime's `nginx_ui_ip_allowlist.lua`;
update the runtime before installing the plugin. Saved site policies and their
source defaults carry both lists through normal peer synchronization. Upgrading
with empty lists preserves legacy replica hashes. No addresses are exempted by
installing the update.
