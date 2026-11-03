# Privileged management extensions in this fork

These approved permission strings extend the host without changing the upstream
manifest schema. Packages remain signed and developer mode is not required.

- `http.privileged`: every plugin HTTP request requires an interactive user and
  the host's secure-session checks. Remote-node selection and service/node
  principals are rejected before proxying. Demo mode cannot use the endpoint.
- `nginx.transaction`: enables `host.runtime.info`, `host.sites.resolve` and
  `host.nginx.transaction`. It grants writes to existing unmanaged site files
  and this plugin's persistent configuration directory. This is a powerful
  permission: review the publisher and its code before approving it.
- `lifecycle.deactivate`: explicit disable and uninstall first call
  `plugin.deactivate` with `{"reason":"disable"}` or `{"reason":"uninstall"}`.
  Explicit enable and enabled installation also wait for `plugin.activate` to
  return `{"activated":true}` after initialization and enforcement restoration.
  The plugin must finish detaching its enforcement, including reporting any
  peer failures, before returning `{"deactivated":true}`. A failure leaves the
  plugin enabled with an error. Process crashes, updates and host shutdown do
  not call this method. A crashed plugin must be recovered before it can
  safely confirm explicit deactivation.

`host.runtime.info` returns `instance_id`, `nginx_conf_dir` and `persistent_dir`.
The last is `<nginx_conf_dir>/plugins-persistent/<plugin-id>` and survives plugin
uninstall. Saved policies can therefore be retained while their active includes
are detached. Re-enable is responsible for restoring those includes through a
validated transaction; it must not merely change a UI indicator.

`host.sites.resolve` accepts `{"name":"example.conf"}` and returns `{"path":...}`.
It rejects ingress-managed sites, path traversal and nonregular files.

`host.nginx.transaction` accepts `{"files":[{"path":...,"content":...,
"expected_sha256":...}],"reload":true}`. `delete:true` removes a plugin-owned
file; deleting a site is not permitted. The expected digest is mandatory; use
`"missing"` for a new file. Maximum 256 files, 1 MiB per existing or new file,
and 3 MiB for the JSON request. Symlinks and paths outside the allowed roots
are rejected. The host serializes all changes with other Nginx mutations,
replaces files atomically, validates the complete configuration and reloads.
A failed validation restores files; a failed reload restores and reloads the
previous configuration. Rollback failures are reported instead of success.

This contract does not authorize changing `nginx.conf`, global modules, external
CrowdSec engine configuration or another plugin's persistent files. A plugin
must detect unsupported external/global enforcement and explain why it cannot
fully deactivate it. It must not report all protection disabled while such
protection remains active. Existing global initialization-only Lua hooks do not
constitute request enforcement.

These extensions do not sandbox native plugins. They run under the host's OS
identity; package signatures establish publisher identity, not code safety.
