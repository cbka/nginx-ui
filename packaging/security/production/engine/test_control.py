import http.client,importlib.util,json,pathlib,tempfile,threading,unittest,sys
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('control',pathlib.Path(__file__).with_name('control.py'))
c=importlib.util.module_from_spec(spec);sys.modules[spec.name]=c;spec.loader.exec_module(c)
class TestControl(unittest.TestCase):
 def test_allowlist(self):
  for args in [['decisions','list','-o','json','--limit','100','--no-simu'],['scenarios','list','-o','json'],['scenarios','install','crowdsecurity/nginx-req-limit'],['decisions','delete','--id','12'],['decisions','add','--ip','192.0.2.1','--duration','5m','--reason','test','--type','ban']]:self.assertTrue(c.allowed(args))
  for args in [None,[],['machines','add','evil'],['scenarios','install','../../etc/passwd'],['scenarios','install','a/b','--force'],['decisions','delete','--id','0'],['decisions','add','--ip','bad','--duration','1h','--reason','x','--type','ban'],['decisions','add','--ip','192.0.2.1','--duration','5m','--reason','x\nfoo','--type','ban']]:self.assertFalse(c.allowed(args))
 def test_empty_secret_rejected_and_requests_authenticated(self):
  with tempfile.TemporaryDirectory() as d:
   token=pathlib.Path(d)/'token';token.write_text('')
   with patch.object(c,'TOKEN',token),patch.object(c,'invoke') as invoke:
    with self.assertRaises(ValueError):c.control_token()
    server=c.http.server.HTTPServer(('127.0.0.1',0),c.Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    def request(auth,args):
     con=http.client.HTTPConnection(*server.server_address,timeout=3)
     con.request('POST','/cscli',json.dumps({'args':args}),{'Authorization':auth,'Content-Type':'application/json'})
     r=con.getresponse();r.read();code=r.status;con.close();return code
    try:
     self.assertEqual(request('Bearer ',['scenarios','list','-o','json']),503)
     token.write_text('a'*64)
     self.assertEqual(request('Bearer wrong',['scenarios','list','-o','json']),401)
     self.assertEqual(request('Bearer '+'a'*64,['machines','add','evil']),400)
     invoke.assert_not_called()
     invoke.return_value='[]'
     self.assertEqual(request('Bearer '+'a'*64,['scenarios','list','-o','json']),200)
     invoke.assert_called_once_with(['/usr/bin/cscli','scenarios','list','-o','json'])
    finally:server.shutdown();server.server_close();thread.join()
 def test_parallel_dashboard_reads_wait_for_short_operation(self):
  import concurrent.futures,time
  entered=threading.Event();release=threading.Event()
  def invoke(*args):
   entered.set();release.wait(1);return '[]'
  with patch.object(c,'control_token',return_value='a'*64),patch.object(c,'invoke',side_effect=invoke):
   server=c.BoundedServer(('127.0.0.1',0),c.Handler)
   thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
   def request():
    con=http.client.HTTPConnection(*server.server_address,timeout=3)
    try:
     con.request('POST','/cscli',json.dumps({'args':['scenarios','list','-o','json']}),{'Authorization':'Bearer '+'a'*64})
     r=con.getresponse();r.read();return r.status
    finally:con.close()
   try:
    with concurrent.futures.ThreadPoolExecutor(max_workers=2)as pool:
     first=pool.submit(request);self.assertTrue(entered.wait(1))
     second=pool.submit(request);time.sleep(.1);release.set()
     self.assertEqual([first.result(),second.result()],[200,200])
   finally:release.set();server.shutdown();server.server_close();thread.join()
 def test_sharing_rollback(self):
  initial={'api':{'server':{'online_client':{'sharing':True}}}}
  with tempfile.TemporaryDirectory() as d:
   file=pathlib.Path(d)/'config';file.write_text(json.dumps(initial))
   with patch.object(c,'CONFIG',file),patch.object(c,'reload_engine',side_effect=[RuntimeError('failed'),None]) as reload:
    with self.assertRaises(RuntimeError):c.set_sharing(False)
    self.assertEqual(json.loads(file.read_text()),initial);self.assertEqual(reload.call_count,2)
   initial['api']['server']['online_client']['sharing']='false';file.write_text(json.dumps(initial))
   with patch.object(c,'CONFIG',file):
    with self.assertRaises(ValueError):c.config()
 def test_reload_validation_never_contacts_capi(self):
  with patch.object(c,'invoke') as invoke,patch.object(c,'engine_ready',return_value=True):
   c.reload_engine()
   self.assertEqual(invoke.call_args_list[0].args[0],['/usr/local/bin/crowdsec','-c',str(c.CONFIG),'-t','-no-capi'])
 def test_malformed_sharing_boolean_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   file=pathlib.Path(d)/'config'
   for bad in ['false','true',0,1,None,[],{}]:
    file.write_text(json.dumps({'api':{'server':{'online_client':{'sharing':bad}}}}))
    with patch.object(c,'CONFIG',file):
     with self.assertRaises(ValueError):c.config()
 def test_scenario_transactions(self):
  for operation in ['install','remove']:
   for failure in ['none','command','reload']:
    with self.subTest(operation=operation,failure=failure),tempfile.TemporaryDirectory() as d:
     root=pathlib.Path(d)/'config';root.mkdir();file=root/'config.yaml'
     file.write_text(json.dumps({'api':{'server':{'online_client':{'sharing':False}}}}))
     hub=root/'hub';hub.mkdir();(hub/'old.yaml').write_text('old')
     scenarios=root/'scenarios';scenarios.mkdir();(scenarios/'old.yaml').symlink_to(hub/'old.yaml')
     def mutate(args, timeout=12):
      (hub/'old.yaml').write_text('changed');(scenarios/'old.yaml').unlink();(scenarios/'new.yaml').write_text('new')
      if failure=='command':raise RuntimeError('partial install')
      return 'ok'
     reload_effect=[RuntimeError('validation failed'),None] if failure=='reload' else None
     with patch.object(c,'CONFIG',file),patch.object(c,'invoke',side_effect=mutate),patch.object(c,'reload_engine',side_effect=reload_effect) as reload:
      if failure=='none':
       self.assertEqual(c.scenario_change(['scenarios',operation,'crowdsecurity/test']),'ok');self.assertEqual(reload.call_count,1)
      else:
       with self.assertRaisesRegex(RuntimeError,'previous configuration restored'):c.scenario_change(['scenarios',operation,'crowdsecurity/test'])
       self.assertEqual((hub/'old.yaml').read_text(),'old');self.assertTrue((scenarios/'old.yaml').is_symlink());self.assertFalse((scenarios/'new.yaml').exists())
       self.assertEqual(reload.call_count,2 if failure=='reload' else 1)
 def test_scenario_rejects_external_symlinks_before_command(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d)/'config';root.mkdir();file=root/'config.yaml'
   file.write_text(json.dumps({'api':{'server':{'online_client':{'sharing':False}}}}))
   (root/'escape').symlink_to('/outside-snapshot')
   with patch.object(c,'CONFIG',file),patch.object(c,'invoke') as invoke:
    with self.assertRaisesRegex(RuntimeError,'symlink escapes'):c.scenario_change(['scenarios','install','crowdsecurity/test'])
    invoke.assert_not_called()
class ReloadReadinessTest(unittest.TestCase):
 def test_waits_for_managed_appsec_before_success(self):
  import appsec
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);(root/'acquis.d').mkdir();(root/'acquis.d/nginx-ui-appsec.yaml').write_text('{}')
   with patch.object(c,'CONFIG',root/'config.yaml'),patch.object(c,'invoke'),patch.object(c,'engine_ready',return_value=True),patch.object(appsec,'runtime_verified',side_effect=[False,True]),patch.object(c.time,'sleep') as sleep:
    c.reload_engine();sleep.assert_called_once()

if __name__=='__main__':unittest.main()
