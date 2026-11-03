import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from audit_normalizer import modsecurity, crowdsec, site_identity, structured_crowdsec, event_time


class NormalizerTests(unittest.TestCase):
    def sample(self):
        return {"transaction": {"unique_id": "request-123", "client_ip": "192.0.2.8",
            "node": "forged-node", "request": {"method": "POST", "uri": "/api?q=topsecret",
            "headers": {"Host": "forged.example", "Authorization": "topsecret"}, "body": "topsecret"},
            "response": {"http_code": 403, "body": "topsecret"}, "producer": {"secrules_engine": "Enabled"},
            "messages": [{"message": "secret topsecret", "details": {"ruleId": "949110", "data": "topsecret", "match": "against variable `ARGS:password' (Value: `topsecret' )"}}]}}

    def test_sensitive_content_is_removed_and_metadata_authoritative(self):
        rows = modsecurity(self.sample(), "kub1", "trusted-site")
        self.assertEqual(len(rows), 1)
        self.assertNotIn("topsecret", json.dumps(rows))
        self.assertNotIn("forged", json.dumps(rows))
        self.assertEqual(rows[0]["path"], "/api")
        self.assertEqual(rows[0]["parameter"], "ARGS:password")
        self.assertEqual(rows[0]["action"], "blocked")
        self.assertEqual(rows[0]["node"], "kub1")
        self.assertEqual(rows[0]["vhost"], "trusted-site")

    def test_same_request_distinct_rule_events_stable_ids(self):
        sample = self.sample()
        sample["transaction"]["messages"] *= 2
        first = modsecurity(sample, "kub1", "site")
        self.assertNotEqual(first[0]["event_id"], first[1]["event_id"])
        self.assertEqual(first, modsecurity(sample, "kub1", "site"))

    def test_detection_mode_never_claims_blocking_from_app_403(self):
        sample = self.sample()
        sample["transaction"]["producer"]["secrules_engine"] = "DetectionOnly"
        self.assertEqual(modsecurity(sample, "kub1")[0]["action"], "detected")
        self.assertEqual(modsecurity(sample, "kub1")[0]["vhost"], "")

    def test_trusted_filename_mapping_rejects_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = hashlib.sha256(b"site.conf").hexdigest() + ".json"
            metadata = Path(directory) / filename
            metadata.write_text(json.dumps({"name": "site.conf"}))
            self.assertEqual(site_identity(filename, directory), "site.conf")
            metadata.write_text(json.dumps({"name": "other-site"}))
            with self.assertRaises(ValueError):
                site_identity(filename, directory)

    def test_bouncer_host_is_unattributed_without_trusted_site_mapping(self):
        line = '2026/11/03 10:00:00 [alert] 37#37: *17 [lua] crowdsec.lua:902: Allow(): [Crowdsec] denied \'192.0.2.8\' with \'ban\' (by bouncer), client: 192.0.2.8, server: primary.example, request: "GET /x?token=topsecret HTTP/1.1", host: "forged.example"'
        row = crowdsec(line, "kub2")[0]
        self.assertEqual(row["vhost"], "")
        self.assertEqual(row["path"], "/x")
        self.assertNotIn("topsecret", json.dumps(row))
        self.assertNotIn("forged", json.dumps(row))
        self.assertEqual(row["scenario"], "")

    def test_original_timestamp_preserved(self):
        self.assertEqual(event_time('Tue Nov  3 10:07:08 2026'), '2026-11-03T10:07:08Z')
        self.assertEqual(event_time('2026-11-03T11:07:08+01:00'), '2026-11-03T10:07:08Z')
        self.assertEqual(event_time('not a timestamp'), '')
        value = self.sample(); value['transaction']['time_stamp'] = 'Tue Nov  3 10:07:08 2026'
        self.assertEqual(modsecurity(value,'kub1')[0]['event_time'], '2026-11-03T10:07:08Z')
    def test_structured_remediation_uses_trusted_site_hash_and_ignores_suffix(self):
        with tempfile.TemporaryDirectory() as directory:
            key=hashlib.sha256(b'site.conf').hexdigest()
            (Path(directory)/(key+'.json')).write_text(json.dumps({'name':'site.conf'}))
            event={'site_id':key,'action':'ban','event_time':'2026-11-03T10:00:00Z','transaction_id':'r1','client_ip':'192.0.2.8','path':'/safe?secret=hidden'}
            line='2026/11/03 10:00:00 [warn] 1#1: *1 [lua] nginx_ui_security_events.lua:20: emit(): NGINX_UI_SECURITY_EVENT '+json.dumps(event)+', host: "forged", request: "GET /?secret=hidden"'
            rows=structured_crowdsec(line,'kub2',directory)
            self.assertEqual(rows[0]['vhost'],'site.conf')
            self.assertEqual(rows[0]['event_time'],'2026-11-03T10:00:00Z')
            self.assertNotIn('hidden',json.dumps(rows))
            self.assertNotIn('forged',json.dumps(rows))
            self.assertEqual(rows[0]['scenario'],'')
    def test_invalid_records_do_not_become_events(self):
        self.assertEqual(modsecurity({}, "kub1"), [])
        self.assertEqual(crowdsec("ordinary application error", "kub1"), [])


if __name__ == "__main__":
    unittest.main()
