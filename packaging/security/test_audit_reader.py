import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from audit_reader import Reader


class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.audit, self.policy = self.root/'audit', self.root/'policy'
        self.audit.mkdir(); self.policy.mkdir()
        self.name = hashlib.sha256(b'site.conf').hexdigest()+'.json'
        (self.policy/self.name).write_text(json.dumps({'name':'site.conf'}))
        self.file = self.audit/self.name
        self.out, self.state = self.root/'events.jsonl', self.root/'state.json'
    def reader(self):
        return Reader(self.audit, self.policy, self.out, self.state, 'kub1')
    def record(self, identity):
        return json.dumps({'transaction':{'unique_id':identity,'request':{'uri':'/x?secret=hidden'},'response':{},'producer':{},'messages':[{'details':{'ruleId':'941100'}}]}})+'\n'
    def rows(self):
        return [json.loads(line) for line in self.out.read_text().splitlines()]
    def test_restart_only_reads_new_records(self):
        self.file.write_text(self.record('one')); self.reader().scan()
        with self.file.open('a') as f: f.write(self.record('two'))
        self.reader().scan()
        self.assertEqual([r['transaction_id'] for r in self.rows()], ['one','two'])
    def test_rename_rotation_drains_old_file_and_reads_new(self):
        self.file.write_text(self.record('one')); reader=self.reader(); reader.scan()
        with self.file.open('a') as f: f.write(self.record('two'))
        self.file.rename(self.audit/(self.name+'.1'))
        self.file.write_text(self.record('three')); reader.scan()
        self.assertEqual({r['transaction_id'] for r in self.rows()}, {'one','two','three'})
    def test_copytruncate_and_rewrite_reset_cursor(self):
        self.file.write_text(self.record('long-original')*2); reader=self.reader(); reader.scan()
        self.file.write_text(self.record('new')); reader.scan()
        self.assertEqual(self.rows()[-1]['transaction_id'], 'new')
    def test_partial_line_is_not_checkpointed(self):
        line=self.record('one'); self.file.write_text(line[:-3]); reader=self.reader(); reader.scan()
        self.assertFalse(self.out.exists())
        with self.file.open('a') as f: f.write(line[-3:])
        reader.scan(); self.assertEqual(len(self.rows()),1)
    def test_replay_produces_same_deduplication_identity(self):
        self.file.write_text(self.record('one')); self.reader().scan(); self.state.unlink()
        self.reader().scan(); rows=self.rows()
        self.assertEqual(len(rows),2); self.assertEqual(rows[0]['event_id'],rows[1]['event_id'])
    def test_partial_output_crash_fragment_is_removed_before_replay(self):
        self.file.write_text(self.record('one'))
        self.out.write_text('{"incomplete":')
        self.reader().scan()
        self.assertEqual(self.rows()[0]['transaction_id'], 'one')
    def test_oversized_record_discard_continues_across_bounded_scans(self):
        self.file.write_text('x'*2000+'\n'+self.record('valid'))
        reader=self.reader()
        with patch('audit_reader.MAX_LINE',256), patch('audit_reader.MAX_CYCLE_BYTES',512):
            for _ in range(6): reader.scan()
        self.assertEqual([r['transaction_id'] for r in self.rows()], ['valid'])
    def test_structured_crowdsec_feed_and_restart(self):
        error=self.root/'error.log'
        data={'site_id':self.name[:-5], 'action':'ban','transaction_id':'crowd1','event_time':'2026-11-03T10:00:00Z','path':'/x','client_ip':'192.0.2.8'}
        error.write_text('2026/11/03 10:00:00 [warn] 1#1: *1 [lua] nginx_ui_security_events.lua:20: emit(): NGINX_UI_SECURITY_EVENT '+json.dumps(data)+'\n')
        reader=Reader(self.audit,self.policy,self.out,self.state,'kub1',error)
        reader.scan()
        reader=Reader(self.audit,self.policy,self.out,self.state,'kub1',error)
        reader.scan()
        rows=self.rows(); self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['source'],'crowdsec')
        self.assertEqual(rows[0]['vhost'],'site.conf')
        self.assertEqual(rows[0]['event_time'],'2026-11-03T10:00:00Z')
    def test_no_metadata_no_attribution_or_checkpoint(self):
        (self.policy/self.name).unlink(); self.file.write_text(self.record('one')); self.reader().scan()
        self.assertFalse(self.out.exists())
    def test_unrelated_filename_and_symlink_not_read(self):
        (self.audit/'secret.json').write_text(self.record('unrelated'))
        self.file.symlink_to(self.audit/'secret.json'); self.reader().scan()
        self.assertFalse(self.out.exists())


if __name__ == '__main__': unittest.main()
