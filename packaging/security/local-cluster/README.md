# Local three-node security lab

This is a persistent, isolated test environment for the Nginx UI security fork.
It does not connect to production. Three independent Nginx/UI instances use their
own databases and configuration. Node 1 is the controller; nodes 2 and 3 receive
explicit signed policy synchronization.

## Open

| Service | Local URL |
| --- | --- |
| Request generator and node links | http://127.0.0.1:4184 |
| Nginx UI node 1 / controller | http://127.0.0.1:4181 |
| Nginx UI node 2 | http://127.0.0.1:4182 |
| Nginx UI node 3 | http://127.0.0.1:4183 |
| Test websites 1 / 2 / 3 | http://127.0.0.1:8181 / http://127.0.0.1:8182 / http://127.0.0.1:8183 |

Login details, TOTP secrets and recovery codes are stored only in
`state/credentials.json` (mode 0600, ignored by Git). Administrators were created
through the normal setup and MFA APIs. To display the current second-factor code:

```sh
python3 packaging/security/local-cluster/bootstrap.py otp node1
```

Use node2 or node3 for the other accounts. Do not upload the state directory or
runtime-secrets.json to a repository.

## Generate traffic

Open the generator, choose a node or all three, profile, rate and duration, then
start. Nothing starts automatically. Stop cancels further sends; an in-flight
request can take up to its two-second network timeout.

Profiles are normal, SQL injection, XSS, scanner and mixed traffic. There is no
20-request/second or 300-second ceiling. A rate of zero requests maximum throughput;
a duration of zero runs until stopped. Choose parallel workers (default 16, up to
256 in-flight requests) to use available capacity. The rate setting is a global
target, not a throughput guarantee. The generator has no unbounded request queue.
The UI shows measured throughput, response statuses, latencies per node and the
last 200 requests. It accepts no arbitrary target URL or payload and follows no
redirects. Docker still bounds the generator to 256 MiB RAM, no swap, two CPUs
and 512 processes/threads to protect the local machine.

The shared test host is `security-demo.local`. The generator sets that Host header;
local website links use the test site's default virtual host. SQL injection and
XSS exercise OWASP CRS. `/.env` exercises the managed exact-path block. Other
scanner paths can legitimately return 200 from the demo handler; a scan-shaped
URL is not automatically an attack blocked by CRS.

## Logs and CrowdSec scope

The local Loki and Alloy services collect normalized security events from all
three nodes. The Security Center can filter by node and virtual host. Raw request
bodies, headers and query strings are not collected in this shared feed.

CrowdSec runs a real local API for decisions and bouncer enforcement, with its
acquisition/scenario engine and Central API disabled. It therefore does not
learn bans automatically from scanner requests. Manual test decisions can be
managed through the Security Center. Community sharing is explicitly false and
no community reporting or downloads are enabled. This is not a simulation of
CrowdSec's public reputation service.

## Lifecycle

From the repository root:

```sh
docker compose -f packaging/security/local-cluster/compose.yaml ps
docker compose -f packaging/security/local-cluster/compose.yaml stop
docker compose -f packaging/security/local-cluster/compose.yaml up -d
```

`stop` preserves all test data. `down` removes the lab containers and network but
keeps bind-mounted state. Keep state until the test environment is no longer
needed; removing it loses users, policies, logs and decisions. Initialization
refuses to overwrite existing state.

All application services use an internal Docker network. A fixed-destination
local gateway also uses a separate edge network and exposes only loopback host
ports; it is not an open proxy. Services
have hard memory/swap, CPU and PID limits and bounded Docker log files. These lab
containers, their state, both networks and the existing fork image are intentionally
retained for the user's testing.

Local raw Nginx/audit files in `state/node*/logs` are not subject to Loki's 48-hour
retention. This is a test lab; monitor disk use and archive/remove old local test
logs when keeping it for extended testing. Community-setting editing is unavailable
in this lab because no engine validation/restart adapter is installed; the actual
persisted setting is readable as disabled.

Acceptance included real three-node WAF responses, temporary CrowdSec ban/removal,
central normalized events through the authenticated application API, and browser
Start/Stop. No test ban or automatic traffic generator run was left active.
