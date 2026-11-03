# Local three-node security lab

## Acceptance
- Three independent Nginx UI/Nginx containers using the current fork image, each
  with persistent local state, available only on loopback host ports.
- Regular application APIs initialize administrators and pair nodes; no direct
  database seeding. A test website policy can be synchronized to peers.
- Real WAF requests and node-attributed events visible through shared local Loki.
- A separate request generator offers normal, SQL injection, XSS and scanner
  profiles, fixed local targets, bounded rates/durations and a responsive stop.
- The generator does not accept arbitrary destinations or follow redirects.
- Fixed Docker memory, CPU and PID limits; no swap growth; no production targets.
- Community reporting stays off; no cloud telemetry intentionally enabled.
- Provide user URLs, local credential file, start/stop commands and honest known
  limitations. Keep these user-requested services, data and network for testing;
  remove only temporary verification resources.

## Work split
Runtime agent owns Compose and service configuration. Backend agent owns API-only
bootstrap and pairing. Frontend agent owns the faker service and its tests. Root
owns integration, browser checks and operator documentation. No concurrent builds.

## Verified during handover
- Browser normal run: six requests, two per node, all HTTP 200.
- Browser mixed run: 72 requests at six/second for twelve seconds. Each node:
  24 total, 15 HTTP 200 and nine HTTP 403, no network failures.
- API setup created independent administrators with MFA. Node 1 paired to both
  peers using Ed25519; site-policy replicas verified through their normal APIs.
- Faker unit/HTTP tests cover allowed targets, profiles, rate/duration limits,
  stop behavior, request bounds and cross-origin command rejection.
- Real CrowdSec decision: all three nodes returned 200 before, 403 during the test
  ban and 200 after removal. No test ban remains.
- Authenticated Security Center events API returned 111 normalized WAF events
  (37 per node) and three CrowdSec events (one per node).
- Sharing status: configured true, enabled false, editable false, runtime_verified
  false. Real local engine uses sharing=false and has no CAPI connection.
- Browser Start/Stop verified; generator left stopped, no background traffic.
- Eight intended services and two lab networks retained, zero restart loops;
  aggregate hard RAM 3712 MiB, no container swap. No temporary test containers left.

## Browser error correction
- Reproduced scenarios HTTP 502 with a healthy empty decisions HTTP 200. Cause:
  deliberately offline LAPI-only lab lacked an explicit empty Hub index.
- Initialize an empty offline catalogue, preserve existing state, and show each
  CrowdSec list's errors independently. A failed scenario read must not label a
  successful empty decision list unavailable.
- Complete expected conf.d/stream directory/includes in fresh and current lab
  configurations. Validate with nginx -t before reload; never suppress self-checks.
- Acceptance: all browser self-checks green, both CrowdSec API reads successful,
  correct empty-state text, focused partial-failure regression tests, rebuilt
  embedded UI/image, and unchanged normal200/XSS403 on each node.

## Higher-load faker
- Remove the 20 req/s and 300-second product limits. Rate zero means maximum
  throughput; duration zero means run until stopped.
- Add real concurrent requests with bounded in-flight work, global pacing and
  measured throughput. Retain fixed local targets, no redirects and CSRF checks.
- Acceptance: tests for high requested rates, concurrency/stop and bounded work;
  actual browser run above 20 req/s followed by Stop; no errors/restart loops.
- Faker resource budget becomes 256 MiB, two CPUs, 512 PIDs, no swap. Aggregate
  lab hard RAM becomes 3840 MiB (3.75 GiB); workload rate has no 20 req/s ceiling.
- Browser acceptance: requested 500 req/s mixed traffic for five seconds, measured
  476.8 req/s and 2,385 requests (795 per node), no network errors. Run ended;
  generator left stopped. Independent concurrency/target-safety review passed.
