# Hourly rule maintenance

The CRS updater checks authenticated Debian trixie, trixie-security and
trixie-updates repositories every 3600 seconds (plus bounded check duration).
APT's existing archive keyring authenticates repository metadata and package
hashes. It downloads only `modsecurity-crs`; it never installs packages or runs
package maintainer scripts, and leaves the runtime's frozen APT sources intact.

Updates remain on the initial major/minor CRS line. A different major/minor
candidate is reported as requiring migration rather than silently changing rule
semantics or the existing `crs-setup.conf`. The existing setup, generated policies,
IP exceptions and per-site rule exclusions remain untouched.

Downloaded content is stored on each node's existing nginx-ui data volume under
`security-rule-updates/crs`. A symlink selects the rule tree. Before reload, the
complete existing NGINX configuration is tested. Failed validation/reload restores
the previous tree and reloads it. Only a successful apply updates `active.json`.
Startup restores the last successfully applied tree before NGINX starts. With no
newer candidate, neither NGINX nor its sessions are reloaded. The original image
rule tree remains available as a fallback. Peers check independently with a short
startup stagger; `status.json` records each node's active version and last result.

The scheduler is a supervised process inside the proxy image, not a workstation
or assistant automation. A file lock prevents overlap. Updating rules does not
enable a disabled security plugin or change a VHost's protection mode.

`python3 crs_update.py --once` performs a supervised manual check; `--restore` is
startup-only. `test_crs_update.py` covers activation, validation/reload failures,
major-version rejection and no-op behavior.
