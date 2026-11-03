import importlib.util,json,pathlib,tempfile,threading,unittest
from unittest.mock import patch

def load(name):
 spec=importlib.util.spec_from_file_location(name,pathlib.Path(__file__).with_name(name+'.py'))
 obj=importlib.util.module_from_spec(spec);spec.loader.exec_module(obj);return obj
c=load('control');h=load('hub_update')

class HubUpdateTest(unittest.TestCase):
 def setup_tree(self,base):
  root=base/'config';root.mkdir();hub=root/'hub';hub.mkdir();scenarios=root/'scenarios';scenarios.mkdir()
  (hub/'.index.json').write_text('{"old":true}')
  (hub/'on.yaml').write_text('old');(hub/'off.yaml').write_text('disabled')
  (scenarios/'on.yaml').symlink_to(hub/'on.yaml');(scenarios/'regular.yaml').write_text('old-regular')
  config=root/'config.yaml'
  config.write_text(json.dumps({'api':{'server':{'online_client':{'sharing':False}}},'config_paths':{'data_dir':str(base/'data'),'index_path':str(hub/'.index.json')}}))
  (base/'data').mkdir();(base/'data/crowdsec.db').write_text('live-db');(base/'data/lookup.txt').write_text('old-lookup')
  return root,config
 def test_update_activation_and_rollback(self):
  for fail in ('none','command','reload','sharing'):
   with self.subTest(fail=fail),tempfile.TemporaryDirectory() as temp:
    base=pathlib.Path(temp);root,config=self.setup_tree(base);calls=[]
    def invoke(args,timeout=12):
     calls.append(args)
     if args[1:]==['hub','update']:(root/'hub/.index.json').write_text('{"new":true}')
     if args[1:]==['hub','upgrade']:
      (root/'hub/on.yaml').write_text('new')
      (base/'data/lookup.txt').write_text('new-lookup')
      (root/'scenarios/off.yaml').symlink_to(root/'hub/off.yaml')
      (root/'scenarios/regular.yaml').write_text('new-regular')
      if fail=='sharing':config.write_text('{}')
      if fail=='command':raise RuntimeError('partial update')
     if args[1:]==['hub','list','-o','json']:return '{"scenarios":[{"name":"vendor/on","version":"1.2"}]}'
     return ''
    effects=[RuntimeError('bad config'),None] if fail=='reload' else None
    with patch.object(c,'CONFIG',config),patch.object(c,'invoke',side_effect=invoke),patch.object(c,'reload_engine',side_effect=effects) as reload,patch.object(h,'STATUS',base/'data/status.json'),patch.object(h,'PROCESS_LOCK',base/'update.lock'):
     self.assertTrue(h.run_once(c));status=json.loads(h.STATUS.read_text())
     self.assertEqual(status['status'],'success' if fail=='none' else 'failure')
     self.assertFalse((root/'scenarios/off.yaml').exists(),'disabled scenario must remain disabled')
     self.assertTrue((root/'scenarios/on.yaml').is_symlink())
     self.assertEqual((root/'hub/on.yaml').read_text(),'new' if fail=='none' else 'old')
     self.assertEqual((root/'scenarios/regular.yaml').read_text(),'new-regular' if fail=='none' else 'old-regular')
     self.assertEqual(json.loads(config.read_text())['api']['server']['online_client']['sharing'],False)
     self.assertEqual((base/'data/crowdsec.db').read_text(),'live-db')
     self.assertEqual((base/'data/lookup.txt').read_text(),'new-lookup' if fail=='none' else 'old-lookup')
     if fail=='none':
      self.assertEqual(len(status['version']['hub_index_sha256']),64)
      self.assertEqual(status['version']['installed_versions'][0]['version'],'1.2')
      self.assertEqual(reload.call_count,1)
     self.assertFalse(any('--force' in command or 'capi' in command for command in calls))
 def test_overlap_does_not_mutate(self):
  with patch.object(c,'LOCK',threading.Lock()),patch.object(c,'configuration_transaction') as tx:
   c.LOCK.acquire()
   try:self.assertFalse(h.run_once(c));tx.assert_not_called()
   finally:c.LOCK.release()
 def test_process_overlap_does_not_mutate(self):
  with tempfile.TemporaryDirectory() as temp:
   path=pathlib.Path(temp)/'lock'
   with path.open('a') as file,patch.object(h,'PROCESS_LOCK',path),patch.object(c,'configuration_transaction') as tx:
    h.fcntl.flock(file,h.fcntl.LOCK_EX|h.fcntl.LOCK_NB)
    self.assertFalse(h.run_once(c));tx.assert_not_called()
 def test_unchanged_rules_do_not_reload(self):
  with tempfile.TemporaryDirectory() as temp:
   base=pathlib.Path(temp);root,config=self.setup_tree(base)
   def invoke(args,timeout=12):
    if args[1:]==['hub','update']:(root/'hub/.index.json').write_text('{"catalog_changed_only":true}')
    if args[1:]==['hub','list','-o','json']:return '{}'
    return ''
   with patch.object(c,'CONFIG',config),patch.object(c,'invoke',side_effect=invoke),patch.object(c,'reload_engine') as reload,patch.object(h,'STATUS',base/'data/status.json'),patch.object(h,'PROCESS_LOCK',base/'update.lock'):
    self.assertTrue(h.run_once(c));reload.assert_not_called()
    status=json.loads(h.STATUS.read_text());self.assertEqual(status['status'],'success');self.assertFalse(status['changed'])
 def test_dataset_changes_reload_but_database_changes_do_not(self):
  for dataset in (False,True):
   with self.subTest(dataset=dataset),tempfile.TemporaryDirectory() as temp:
    base=pathlib.Path(temp);root,config=self.setup_tree(base)
    def invoke(args,timeout=12):
     if args[1:]==['hub','upgrade']:
      (base/'data/crowdsec.db').write_text('live-db-progress')
      if dataset:(base/'data/lookup.txt').write_text('new-lookup')
     if args[1:]==['hub','list','-o','json']:return '{}'
     return ''
    with patch.object(c,'CONFIG',config),patch.object(c,'invoke',side_effect=invoke),patch.object(c,'reload_engine') as reload,patch.object(h,'STATUS',base/'data/status.json'),patch.object(h,'PROCESS_LOCK',base/'update.lock'):
     self.assertTrue(h.run_once(c));self.assertEqual(reload.call_count,int(dataset))
 def test_scheduler_respects_persistent_interval(self):
  class Stop:
   def __init__(self): self.waits=0
   def wait(self,seconds): self.waits+=1; return self.waits>=2
   def is_set(self):return self.waits>=2
  for last,expected in [(9999,0),(0,1)]:
   with self.subTest(last=last),patch.object(h,'read_status',return_value={'last_attempt_epoch':last}),patch.object(h.time,'time',return_value=10000),patch.object(h,'run_once') as run:
    h.scheduler(c,Stop());self.assertEqual(run.call_count,expected)
if __name__=='__main__':unittest.main()
