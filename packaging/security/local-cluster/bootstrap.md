# Local API bootstrap

Run `python3 packaging/security/local-cluster/bootstrap.py` after the local cluster
is reachable. Python `cryptography` is required. The script is restricted to the
three fixed loopback UI endpoints and their task-owned containers.

Bootstrap uses the normal first-run installation, RSA-encrypted login, TOTP
registration, protected settings and node/site APIs. It never writes SQLite or
manufactures authentication/session tokens. The only container file it reads is
the one-time `.install_secret`; it does not print that value. Initial node secrets
are retrieved through the MFA-protected API, passed to normal node registration,
and automatically upgraded by Nginx UI to paired Ed25519 credentials.

Credentials, TOTP secrets and recovery codes are stored in
`state/credentials.json` with mode `0600`. Open that local file for the per-node
username/password. To obtain a current TOTP explicitly:

```
python3 packaging/security/local-cluster/bootstrap.py otp node1
```

The default setup is a controller (`node1`) with two independent paired peers.
Each has its own application database, identity and login. The bootstrap registers
`security-demo.conf` synchronization membership through the site API, applies a
local WAF policy and checks both paired replicas. Re-running preserves saved
credentials and registered relationships. Template/sample policy application is
restricted to this named lab site. A completed rerun reapplies the lab baseline,
so do not rerun merely to obtain a login code after making experimental changes.

The script fails on unexpected authentication errors rather than repeatedly
trying passwords. API error bodies and tokens are not printed. Setup must happen
within the application's first-run installation window. Reset/recreate only the
explicit lab state if an installation window has expired; never edit the DB to
bypass installation or MFA.
