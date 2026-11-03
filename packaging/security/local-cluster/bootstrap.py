#!/usr/bin/env python3
"""Bootstrap only the isolated three-node lab through normal Nginx UI APIs.
Requires Python cryptography. Never modifies SQLite or bypasses authentication.
"""
import argparse
import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

NODES = {f"node{i}": f"http://127.0.0.1:{4180+i}" for i in range(1, 4)}
SITE = "security-demo.conf"

class LabError(Exception):
    pass

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise LabError("Unexpected redirect refused")

def totp(secret, timestamp=None):
    timestamp = time.time() if timestamp is None else timestamp
    key = base64.b32decode(secret + "=" * ((-len(secret)) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", int(timestamp // 30)), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f"{(struct.unpack('>I', digest[offset:offset+4])[0] & 0x7fffffff) % 1000000:06d}"

def save_credentials(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or (path.exists() and path.stat().st_mode & 0o077):
        raise LabError("Credential file must be regular, private mode 0600")
    fd, temporary = tempfile.mkstemp(prefix=".bootstrap-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

class Client:
    def __init__(self, name):
        self.name = name
        self.base = NODES[name]
        self.headers = {"Content-Type": "application/json"}
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, method, path, body=None, headers=None, timeout=40):
        request = urllib.request.Request(self.base + "/api" + path, data=None if body is None else json.dumps(body).encode(), method=method, headers=self.headers | (headers or {}))
        try:
            with self.opener.open(request, timeout=timeout) as response:
                data = response.read(2 * 1024 * 1024 + 1)
                if len(data) > 2 * 1024 * 1024:
                    raise LabError("API response exceeded local bound")
                return json.loads(data) if data else {}
        except urllib.error.HTTPError as error:
            # Never print response bodies: auth/setup responses can contain secrets.
            raise LabError(f"{self.name}: {method} {path.split('?')[0]} returned HTTP {error.code}") from None
        except (urllib.error.URLError, TimeoutError):
            raise LabError(f"{self.name}: local API unavailable") from None

    def encrypted(self, path, body, headers=None):
        public = self.request("POST", "/crypto/public_key", {"timestamp": int(time.time()), "fingerprint": "isolated-security-lab-bootstrap"})
        key = serialization.load_pem_public_key(public["public_key"].encode())
        ciphertext = key.encrypt(json.dumps(body, separators=(",", ":")).encode(), padding.PKCS1v15())
        return self.request("POST", path, {"encrypted_params": base64.b64encode(ciphertext).decode()}, headers)

    def login(self, credentials, path, all_credentials):
        body = {"name": credentials["username"], "password": credentials["password"]}
        if credentials.get("otp_secret"):
            # Avoid replaying a recently consumed OTP when bootstrap is rerun.
            if credentials.get("login_window") == int(time.time() // 30):
                time.sleep(31 - time.time() % 30)
            body["otp"] = totp(credentials["otp_secret"])
        response = self.encrypted("/login", body)
        if response.get("code") != 200 or not response.get("token"):
            raise LabError(f"{self.name}: login requires operator attention; no repeated guessing")
        self.headers["Authorization"] = "Bearer " + response["token"]
        if response.get("secure_session_id"):
            self.headers["X-Secure-Session-ID"] = response["secure_session_id"]
        credentials["login_window"] = int(time.time() // 30)
        save_credentials(path, all_credentials)

def list_items(value):
    if isinstance(value, list):
        return value
    for key in ("data", "items"):
        if isinstance(value.get(key), list):
            return value[key]
    raise LabError("Unexpected list response shape")

def bootstrap(path):
    if path.is_symlink() or (path.exists() and path.stat().st_mode & 0o077):
        raise LabError("Refusing insecure credential file")
    credentials = json.loads(path.read_text()) if path.exists() else {"nodes": {}}
    clients = {}
    for name in NODES:
        entry = credentials["nodes"].setdefault(name, {"username": "admin", "password": secrets.token_urlsafe(15), "url": NODES[name]})
        save_credentials(path, credentials)
        client = clients[name] = Client(name)
        for attempt in range(30):
            try:
                install = client.request("GET", "/install", timeout=3)
                break
            except LabError:
                if attempt == 29:
                    raise
                time.sleep(2)
        if not install["lock"]:
            result = subprocess.run(["docker", "exec", f"nginx-security-local-{name}", "cat", "/usr/local/etc/nginx-ui/.install_secret"], capture_output=True, check=False, timeout=10)
            if result.returncode:
                raise LabError(f"{name}: installation secret unavailable; check first-run timeout")
            client.encrypted("/setup/install", {"username": entry["username"], "password": entry["password"], "email": "security-lab@example.invalid"}, {"X-Install-Secret": result.stdout.decode().strip()})
        client.login(entry, path, credentials)
        status = client.request("GET", "/2fa_status")
        if not status["otp_status"]:
            entry["otp_secret"] = client.request("GET", "/otp_secret")["secret"]
            save_credentials(path, credentials)
            response = client.request("POST", "/otp_enroll", {"secret": entry["otp_secret"], "passcode": totp(entry["otp_secret"]), "password": entry["password"]})
            entry["recovery_codes"] = response.get("recovery_codes", [])
            save_credentials(path, credentials)
            client.login(entry, path, credentials)
        print(f"{name}: installed and authenticated through normal APIs", flush=True)
    controller = clients["node1"]
    existing = list_items(controller.request("GET", "/nodes"))
    peer_ids = []
    for name in ("node2", "node3"):
        url = f"http://{name}:9000"
        node = next((item for item in existing if item["url"].rstrip("/") == url), None)
        if node is None:
            secret = clients[name].request("GET", "/settings/protected?path=node.secret")["value"]
            node = controller.request("POST", "/nodes", {"name": name, "url": url, "enabled": True, "legacy_secret": secret, "accept_plugin_sync": False})
        for attempt in range(60):
            node = controller.request("GET", f"/nodes/{node['id']}")
            if node.get("auth_method") == "paired_ed25519" and node.get("credential_status") == "active":
                break
            if attempt == 59:
                raise LabError(f"{name}: pairing did not finish; inspect node status")
            time.sleep(2)
        peer_ids.append(node["id"])
        print(f"node1 → {name}: paired Ed25519 authentication active", flush=True)
    current = controller.request("GET", "/sites/" + SITE)
    # Metadata membership is registered via the regular site API before applying
    # managed includes, so ordinary site sync never copies missing policy files.
    if not credentials.get("site_registered"):
        controller.request("POST", "/sites/" + SITE, {"content": current["config"], "overwrite": True, "sync_node_ids": peer_ids, "post_action": ""})
        credentials["site_registered"] = True
        save_credentials(path, credentials)
    controller.request("PUT", "/security-center/modsecurity", {"mode": "On", "paranoia_level": 1, "inbound_threshold": 5, "outbound_threshold": 4, "excluded_rule_ids": [], "crowdsec_enabled": True})
    policy = {"modsecurity": "On", "crowdsec": "inherit", "paranoia_level": 1, "inbound_threshold": 5, "outbound_threshold": 4, "excluded_rule_ids": [], "exceptions": [], "blocked_paths": ["/.env"]}
    controller.request("PUT", "/security-center/sites/" + SITE, policy)
    results = controller.request("POST", "/security-center/sites/" + SITE + "/sync", {})
    if len(results["results"]) != 2 or any(item["status"] not in ("applied", "unchanged") for item in results["results"]):
        raise LabError("Security sync failed for one or more peers; inspect controller UI")
    for name in ("node2", "node3"):
        state = clients[name].request("GET", "/security-center/sites/" + SITE)
        if not state.get("replica") or state["policy"] != policy:
            raise LabError(f"{name}: replicated policy verification failed")
    print("Three independent nodes verified; controller policy synchronized to both peers.")
    print(f"Local login credentials, TOTP secrets and recovery codes: {path} (0600)")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", choices=["bootstrap", "otp"], default="bootstrap")
    parser.add_argument("node", nargs="?", choices=list(NODES))
    parser.add_argument("--credentials", type=Path, default=Path(__file__).resolve().parent / "state" / "credentials.json")
    args = parser.parse_args()
    try:
        if args.command == "otp":
            if not args.node:
                parser.error("otp requires node1, node2 or node3")
            if args.credentials.is_symlink() or args.credentials.stat().st_mode & 0o077:
                raise LabError("Refusing insecure credential file")
            print(totp(json.loads(args.credentials.read_text())["nodes"][args.node]["otp_secret"]))
        else:
            bootstrap(args.credentials)
    except (LabError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        # Avoid dumping arbitrary exceptions/response objects containing secrets.
        print(str(error) if isinstance(error, LabError) else "Local bootstrap failed; inspect configuration and rerun safely", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
