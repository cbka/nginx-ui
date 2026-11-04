import json,pathlib,tempfile,unittest
from unittest.mock import patch
import appsec,control,hub_update
class AppSecTest(unittest.TestCase):
 def test_inventory_status_not_inferred_from_version(self):
  data={'appsec-rules':[{'name':'crowdsecurity/a','status':'disabled,update-available','local_version':'1'}, {'name':'crowdsecurity/b','status':'enabled,tainted','local_version':'2'}]}
  with patch.object(control,'invoke',return_value=json.dumps(data)):
   rows=appsec.rows(control,'appsec-rules')
  self.assertFalse(rows[0]['installed']);self.assertTrue(rows[1]['installed']);self.assertIsNone(rows[1]['loaded'])
 def test_enable_disable_and_rollback(self):
  for failure in [False,True]:
   with self.subTest(failure=failure),tempfile.TemporaryDirectory() as tmp:
    root=pathlib.Path(tmp)/'config';root.mkdir();data=pathlib.Path(tmp)/'data';data.mkdir()
    cfg=root/'config.yaml';original=json.dumps({'api':{'server':{'online_client':{'sharing':False}}},'config_paths':{'data_dir':str(data)}});cfg.write_text(original)
    def invoke(args,**kw):
     if 'list' in args:return json.dumps({'collections':[]})
     (root/'appsec-rules').mkdir(exist_ok=True);(root/'appsec-rules/new.yaml').write_text('rule')
     return ''
    with patch.object(control,'CONFIG',cfg),patch.object(control,'invoke',side_effect=invoke),patch.object(appsec,'ready',return_value=True),patch.object(control,'reload_engine',side_effect=[RuntimeError(),None] if failure else None):
     if failure:
      with self.assertRaises(RuntimeError):appsec.set_enabled(control,True)
      self.assertFalse(appsec.acquisition_path(control).exists());self.assertFalse((root/'appsec-rules').exists())
     else:
      result=appsec.set_enabled(control,True);self.assertTrue(result['enabled'])
      self.assertEqual(json.loads((root/'appsec-configs/nginx-ui-detection.yaml').read_text())['on_match'][0]['apply'],['CancelAlert()','CancelEvent()'])
      self.assertFalse(appsec.set_enabled(control,True)['changed'])
      detection=root/'acquis.d/nginx-ui-appsec-detection.yaml';detection.unlink()
      self.assertFalse(appsec.enabled(control));self.assertTrue(appsec.set_enabled(control,True)['changed'])
      detection.write_text('{}')
      with self.assertRaises(ValueError):appsec.set_enabled(control,True)
      detection.unlink();detection.symlink_to(root/'config.yaml')
      with self.assertRaises(ValueError):appsec.set_enabled(control,True)
      detection.unlink();detection.write_text(json.dumps(appsec.DETECTION))
      appsec.set_enabled(control,False);self.assertFalse(appsec.acquisition_path(control).exists());self.assertTrue((root/'appsec-rules/new.yaml').exists())
     self.assertEqual(cfg.read_text(),original)
 def test_runtime_proof_requires_same_process_fingerprint_and_readiness(self):
  with tempfile.TemporaryDirectory() as tmp:
   receipt=pathlib.Path(tmp)/'receipt';identity={'pid':123,'start_ticks':'100','boot_id':'testboot'}
   receipt.write_text(json.dumps(dict(identity,fingerprint='hash')))
   original=pathlib.Path.read_bytes
   def read(path):
    if str(path)=='/proc/123/cmdline':return b'/usr/local/bin/crowdsec\0-c\0/etc/crowdsec/config.yaml\0'
    return original(path)
   with patch.object(appsec,'START_RECEIPT',receipt),patch.object(appsec,'enabled',return_value=True),patch.object(appsec,'ready',return_value=True) as ready,patch.object(appsec,'process_identity',return_value=identity) as process,patch.object(appsec,'runtime_fingerprint',return_value='hash') as fingerprint,patch.object(pathlib.Path,'read_bytes',read):
    self.assertTrue(appsec.runtime_verified(control))
    ready.return_value=False;self.assertFalse(appsec.runtime_verified(control));ready.return_value=True
    fingerprint.return_value='changed';self.assertFalse(appsec.runtime_verified(control));fingerprint.return_value='hash'
    process.return_value=dict(identity,start_ticks='200');self.assertFalse(appsec.runtime_verified(control))
 def test_loaded_only_managed_rules_after_verified_start(self):
  rules=[{'name':n,'installed':i,'loaded':None} for n,i in [('crowdsecurity/base-config',True),('crowdsecurity/vpatch-test',True),('crowdsecurity/vpatch-disabled',False),('crowdsecurity/experimental-test',True)]]
  with patch.object(appsec,'enabled',return_value=True),patch.object(appsec,'ready',return_value=True),patch.object(appsec,'runtime_verified',return_value=True),patch.object(appsec,'rows',side_effect=lambda c,k:rules if k=='appsec-rules' else []):
   value=appsec.inventory(control)
  self.assertEqual([r['loaded'] for r in value['rules']],[True,True,None,None])
 def test_invalid_boolean(self):
  with self.assertRaises(ValueError):appsec.set_enabled(control,'false')
 def test_upgrade_keeps_new_patch_but_not_disabled_known_patch(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=pathlib.Path(tmp)/'config';root.mkdir();data=pathlib.Path(tmp)/'data';data.mkdir()
   cfg=root/'config.yaml';cfg.write_text(json.dumps({'api':{'server':{'online_client':{'sharing':False}}},'config_paths':{'data_dir':str(data)}}))
   hub=root/'hub';hub.mkdir();(root/'collections').mkdir();(root/'collections/appsec-virtual-patching.yaml').write_text('active')
   old={'collections':{'crowdsecurity/appsec-virtual-patching':{'appsec-rules':['crowdsecurity/old']}},'appsec-rules':{'crowdsecurity/old':{'path':'appsec-rules/crowdsecurity/old.yaml'}}}
   index=hub/'.index.json';index.write_text(json.dumps(old))
   def invoke(args,**kw):
    if args[1:3]==['hub','upgrade']:
     old['collections']['crowdsecurity/appsec-virtual-patching']['appsec-rules'].append('crowdsecurity/new')
     old['appsec-rules']['crowdsecurity/new']={'path':'appsec-rules/crowdsecurity/new.yaml'}
     index.write_text(json.dumps(old));(root/'appsec-rules').mkdir();(hub/'appsec-rules/crowdsecurity').mkdir(parents=True)
     for name in ['old','new']:
      target=hub/('appsec-rules/crowdsecurity/'+name+'.yaml');target.write_text('rule')
      (root/'appsec-rules'/ (name+'.yaml')).symlink_to(target)
    return '{}' if 'list' in args else ''
   with patch.object(control,'CONFIG',cfg),patch.object(control,'invoke',side_effect=invoke):hub_update.upgrade(control)
   self.assertTrue((root/'appsec-rules/new.yaml').is_file())
   self.assertFalse((root/'appsec-rules/old.yaml').exists())
 def test_new_dependency_scope(self):
  result=hub_update.virtual_patch_dependencies({'collections':{'crowdsecurity/appsec-virtual-patching':{'appsec-rules':['crowdsecurity/vpatch-new','evil/new'],'scenarios':['crowdsecurity/appsec-new']}}})
  self.assertEqual(result,{('appsec-rules','crowdsecurity/vpatch-new'),('scenarios','crowdsecurity/appsec-new')})
if __name__=='__main__':unittest.main()
