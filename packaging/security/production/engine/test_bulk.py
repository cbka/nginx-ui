import json,pathlib,tempfile,unittest
from unittest.mock import patch
import control,appsec
import bulk

class BulkTests(unittest.TestCase):
 def test_preview_filters_and_binds_inventory(self):
  rows=[{'name':'crowdsecurity/http-test','available':True,'tainted':False,'installed':False,'version':'1'}, {'name':'local/custom','available':False,'tainted':False,'installed':False}, {'name':'crowdsecurity/changed','available':True,'tainted':True,'installed':False}, {'name':'crowdsecurity/active','available':True,'tainted':False,'installed':True}]
  with patch.object(appsec,'rows',return_value=rows):
   first=bulk.preview(control,'scenarios');self.assertEqual(first['eligible_count'],1);self.assertEqual(first['skipped_count'],3)
   rows[0]['version']='2';self.assertNotEqual(first['preview_id'],bulk.preview(control,'scenarios')['preview_id'])
 def test_appsec_does_not_enable_engine_or_other_profiles(self):
  rows=[{'name':'crowdsecurity/vpatch-a','available':True,'tainted':False,'installed':False}, {'name':'crowdsecurity/other','available':True,'tainted':False,'installed':False}]
  with patch.object(appsec,'rows',return_value=rows),patch.object(appsec,'enabled',return_value=False):
   self.assertEqual(bulk.preview(control,'appsec')['eligible_count'],0)
  with patch.object(appsec,'rows',return_value=rows),patch.object(appsec,'enabled',return_value=True),patch.object(appsec,'runtime_verified',return_value=True):
   self.assertEqual(bulk.preview(control,'appsec')['eligible_count'],1)
 def test_bad_kind_rejected(self):
  with self.assertRaises(ValueError):bulk.preview(control,'../scenarios')
 def test_start_rejects_stale_without_commands(self):
  with tempfile.TemporaryDirectory() as d,patch.object(bulk,'STATE',pathlib.Path(d)),patch.object(bulk,'preview',return_value={'preview_id':'a'*64,'eligible_count':1}):
   with self.assertRaises(ValueError):bulk.start(control,'scenarios','b'*64)
 def test_failed_transaction_never_reports_success(self):
  with tempfile.TemporaryDirectory() as d,patch.object(bulk,'STATE',pathlib.Path(d)),patch.object(control,'configuration_transaction',side_effect=RuntimeError('restored')):
   job={'id':'a'*32,'kind':'scenarios','state':'queued','items':[{'name':'crowdsecurity/test','action':'install','reason':'','state':'pending'}],'total':1,'completed':0}
   bulk.save(job);bulk.work(control,job)
   self.assertEqual(bulk.current()['state'],'failed');self.assertNotEqual(bulk.current()['items'][0]['state'],'succeeded')
 def test_cancel_blocks_admission_until_worker_finishes(self):
  with tempfile.TemporaryDirectory() as d,patch.object(bulk,'STATE',pathlib.Path(d)):
   bulk.save({'id':'a'*32,'state':'running','items':[]});bulk.cancel()
   self.assertTrue(bulk.CANCEL.is_set());self.assertTrue(bulk.CANCELLING.is_set())
   with self.assertRaises(ValueError):bulk.start(control,'scenarios','b'*64)
   self.assertFalse(control.LOCK.locked());bulk.CANCEL.clear();bulk.CANCELLING.clear()
 def test_worker_filesystem_error_releases_control_lock(self):
  control.LOCK.acquire()
  with tempfile.TemporaryDirectory() as d:
   file=pathlib.Path(d)/'notadir';file.write_text('x')
   with patch.object(bulk,'STATE',file):
    bulk.work(control,{},True)
  self.assertFalse(control.LOCK.locked())
 def test_restart_restores_only_configuration_not_data(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d)/'config';root.mkdir();cfg=root/'config.yaml';cfg.write_text('old')
   state=pathlib.Path(d)/'data/bulk';state.mkdir(parents=True);db=state.parent/'crowdsec.db';db.write_text('live-db')
   import shutil
   shutil.copytree(root,state/'recovery-config');cfg.write_text('partially-installed')
   with patch.object(control,'CONFIG',cfg),patch.object(bulk,'STATE',state):
    bulk.save({'id':'a'*32,'state':'running','items':[{'state':'staged'}]});bulk.recover(control)
    self.assertEqual(cfg.read_text(),'old');self.assertEqual(db.read_text(),'live-db');self.assertEqual(bulk.current()['state'],'interrupted')
 def test_transaction_installs_multiple_reloads_once_and_rolls_back_failure(self):
  for fail in (False,True):
   with self.subTest(fail=fail),tempfile.TemporaryDirectory() as d:
    root=pathlib.Path(d)/'config';root.mkdir();data=pathlib.Path(d)/'data';data.mkdir();cfg=root/'config.yaml'
    cfg.write_text(json.dumps({'api':{'server':{'online_client':{'sharing':False}}},'config_paths':{'data_dir':str(data)}}))
    original=cfg.read_bytes();names=['crowdsecurity/one','crowdsecurity/two'];calls=[]
    def invoke(args,**kw):
     calls.append(args);(root/(args[-1].split('/')[-1]+'.yaml')).write_text('new')
     if fail and args[-1]==names[1]:raise RuntimeError('download failed')
     return ''
    job={'id':'a'*32,'kind':'scenarios','state':'queued','items':[{'name':n,'action':'install','reason':'','state':'pending'}for n in names],'total':2,'completed':0}
    with patch.object(control,'CONFIG',cfg),patch.object(bulk,'STATE',data/'bulk'),patch.object(control,'invoke',side_effect=invoke),patch.object(control,'reload_engine')as reload,patch.object(appsec,'rows',return_value=[{'name':n,'installed':True}for n in names]):
     bulk.save(job);bulk.work(control,job)
     self.assertEqual(bulk.current()['state'],'failed'if fail else'succeeded');self.assertEqual(reload.call_count,1)
     self.assertEqual(cfg.read_bytes(),original);self.assertEqual((root/'one.yaml').exists(),not fail)
 def test_failed_preview_can_retry_and_disable_pending_cannot_start(self):
  plan={'kind':'scenarios','preview_id':'a'*64,'eligible_count':1,'items':[{'name':'crowdsecurity/one','action':'install','reason':''}]}
  with tempfile.TemporaryDirectory() as d,patch.object(bulk,'STATE',pathlib.Path(d)),patch.object(bulk,'preview',return_value=plan),patch.object(bulk.threading,'Thread')as thread:
   bulk.save({'id':'b'*32,'kind':'scenarios','preview_id':'a'*64,'state':'failed','items':[]})
   job=bulk.start(control,'scenarios','a'*64);self.assertEqual(job['state'],'queued');self.assertNotEqual(job['id'],'b'*32)
   # Mock worker did not run: release its transferred lock ourselves.
   control.LOCK.release();thread.assert_called_once()
   bulk.DISABLING.set()
   try:
    with self.assertRaises(ValueError):bulk.start(control,'scenarios','a'*64)
    self.assertFalse(control.LOCK.locked())
   finally:bulk.DISABLING.clear()
 def test_cancellation_rolls_back_before_reload(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d)/'config';root.mkdir();data=pathlib.Path(d)/'data';data.mkdir();cfg=root/'config.yaml'
   cfg.write_text(json.dumps({'api':{'server':{'online_client':{'sharing':False}}},'config_paths':{'data_dir':str(data)}}))
   def invoke(args,**kw):(root/'new.yaml').write_text('new');bulk.cancel();return ''
   job={'id':'a'*32,'kind':'scenarios','state':'queued','items':[{'name':'crowdsecurity/one','action':'install','reason':'','state':'pending'}],'total':1,'completed':0}
   with patch.object(control,'CONFIG',cfg),patch.object(bulk,'STATE',data/'bulk'),patch.object(control,'invoke',side_effect=invoke),patch.object(control,'reload_engine')as reload:
    bulk.save(job);bulk.work(control,job)
    self.assertEqual(bulk.current()['state'],'failed');self.assertFalse((root/'new.yaml').exists());self.assertEqual(reload.call_count,1)
    self.assertFalse(bulk.CANCELLING.is_set());bulk.CANCEL.clear()
 def test_thread_start_failure_is_retryable(self):
  plan={'kind':'scenarios','preview_id':'a'*64,'eligible_count':1,'items':[{'name':'crowdsecurity/one','action':'install','reason':''}]}
  with tempfile.TemporaryDirectory() as d,patch.object(bulk,'STATE',pathlib.Path(d)),patch.object(bulk,'preview',return_value=plan),patch.object(bulk.threading,'Thread')as thread:
   thread.return_value.start.side_effect=RuntimeError('no thread')
   with self.assertRaises(RuntimeError):bulk.start(control,'scenarios','a'*64)
   self.assertEqual(bulk.current()['state'],'failed');self.assertFalse(control.LOCK.locked())
 def test_disable_during_preview_does_not_clear_cancellation(self):
  def preview(*args):
   with bulk.STATE_LOCK:bulk.DISABLING.set();bulk.CANCEL.set()
   return {'kind':'scenarios','preview_id':'a'*64,'eligible_count':1,'items':[]}
  with tempfile.TemporaryDirectory() as d,patch.object(bulk,'STATE',pathlib.Path(d)),patch.object(bulk,'preview',side_effect=preview),patch.object(bulk.threading,'Thread')as thread:
   try:
    with self.assertRaises(ValueError):bulk.start(control,'scenarios','a'*64)
    self.assertTrue(bulk.CANCEL.is_set());self.assertFalse(control.LOCK.locked());thread.assert_not_called()
   finally:bulk.DISABLING.clear();bulk.CANCEL.clear()
if __name__=='__main__':unittest.main()
