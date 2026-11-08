"""Executed only by test-request-correlation.sh inside a disposable container."""
import gzip
import json
import re
import urllib.error
import urllib.request

def main():
    ids = set()
    requests = [("/ok?secret=do-not-log", 200), ("/upstream", 200), ("/modsec", 403),
                ("/redirect", 403), ("/html",401), ("/json",401), ("/encoded",503), ("/stream",503), ("/large",503)] + [("/status/" + str(code), code) for code in (401, 403, 500, 502, 503, 504)]
    for path, expected in requests:
        request = urllib.request.Request("http://127.0.0.1:8089" + path,
                                         headers={"X-Request-ID": "client-forged", "Accept-Encoding": "gzip"})
        try:
            response = urllib.request.urlopen(request)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            assert response.code == expected, (path, response.code)
            references = response.headers.get_all("X-Request-ID")
            assert references and len(references) == 1, (path, references)
            reference = references[0]
            assert re.fullmatch("[0-9a-f]{32}", reference), (path, reference)
            assert reference not in ids
            ids.add(reference)
            body_bytes = response.read()
            if response.headers.get("Content-Encoding") == "gzip":
                body_bytes = gzip.decompress(body_bytes)
            body = body_bytes.decode()
            if path == "/redirect":
                assert body.startswith(reference) and "Referenz-ID:" in body and body.count(reference) == 2, (body, reference)
            if path == "/ok?secret=do-not-log":
                assert response.headers["X-Other"] == "preserved"
            if expected in (401, 403, 500, 502, 503, 504) and path not in ("/json", "/encoded", "/large"):
                assert "Referenz-ID:" in body and reference in body, (path, body)
            if path == "/json":
                assert body == '{"error":"authenticate"}' and response.headers["WWW-Authenticate"] == 'Basic realm="test"'
            if path == "/encoded":
                assert "Referenz-ID" not in body and "encoded content" in body
            if path == "/large":
                assert body == "<html><body>" + "x" * 70000 + "</body></html>"
            if path == "/status/403":
                assert response.headers.get("Content-Encoding") == "gzip", "real nginx gzip filter must run after annotation"
            if path.startswith("/status/"):
                assert "nginx" not in body.replace("nginx-ui-request-reference", "")
            if path == "/html":
                assert "Maintenance / login context preserved" in body
                assert body.count('class="nginx-ui-request-reference"') == 1, body
                assert re.findall(r"Referenz-ID: <code>([a-f0-9]{32})</code>", body) == [reference], body
                assert response.headers["WWW-Authenticate"] == 'Basic realm="test"'
            if path == "/modsec":
                modsec_reference = reference

    response = urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:8089/ok", method="HEAD"))
    assert response.read() == b"" and re.fullmatch("[0-9a-f]{32}", response.headers["X-Request-ID"])
    try:
        response = urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:8089/status/403", method="HEAD"))
    except urllib.error.HTTPError as error:
        response = error
    assert response.code == 403 and response.read() == b"" and re.fullmatch("[0-9a-f]{32}", response.headers["X-Request-ID"])
    with open("/var/log/nginx/request-correlation.log") as stream:
        raw = stream.read()
    assert "do-not-log" not in raw and "client-forged" not in raw and "upstream-forged" not in raw
    rows = [json.loads(line) for line in raw.splitlines()]
    assert ids.issubset({row["request_id"] for row in rows})
    with open("/tmp/modsec-audit.json") as stream:
        audits = [json.loads(line) for line in stream if line.strip()]
    assert any(row["transaction"]["unique_id"] == modsec_reference for row in audits)
    print("PASS: fresh server IDs, client/upstream spoof rejection, 200/401/403/500/502/503/504 headers, internal redirect/streamed HTML bodies, JSON/auth/gzip/HEAD preservation, 64KiB bound, correlation access JSON and ModSecurity transaction ID")


if __name__ == "__main__":
    main()
