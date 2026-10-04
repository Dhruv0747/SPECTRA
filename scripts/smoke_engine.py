"""Verify a relocated engine with a storage-only loopback scan; no target probes."""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request


def smoke_engine(bundle):
    bundle = Path(bundle).resolve()
    engine = bundle/'tools/spiderfoot'
    runtime = engine/'runtime/python.exe'
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    base = f'http://127.0.0.1:{port}'
    with tempfile.TemporaryDirectory(prefix='spectra-engine-smoke-') as tmp:
        env = os.environ.copy()
        env['PATH'] = str(Path(os.environ['SystemRoot'])/'System32')
        for key, name in [('SPIDERFOOT_DATA','data'),('SPIDERFOOT_CACHE','cache'),('SPIDERFOOT_LOGS','logs')]: env[key] = str(Path(tmp)/name)
        with (Path(tmp)/'startup.log').open('w') as log:
            p = subprocess.Popen([str(runtime), str(engine/'sf.py'), '-l', f'127.0.0.1:{port}'], cwd=engine, env=env,
                                 stdout=log, stderr=log, creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            try:
                def get(endpoint, data=None):
                    req = urllib.request.Request(base+endpoint, data=data, headers={'Accept':'application/json'})
                    with urllib.request.urlopen(req, timeout=20) as r: return json.load(r)
                for _ in range(50):
                    if p.poll() is not None: raise RuntimeError('Engine exited during startup')
                    try:
                        if get('/ping')[0] == 'SUCCESS': break
                    except OSError: time.sleep(.5)
                else: raise RuntimeError('Engine readiness timed out')
                result = get('/startscan', urllib.parse.urlencode({'scanname':'SPECTRA portable smoke','scantarget':'127.0.0.1','modulelist':'sfp__stor_db','typelist':'','usecase':''}).encode())
                if result[0] != 'SUCCESS': raise RuntimeError('Engine rejected smoke scan')
                for _ in range(40):
                    status = get('/scanstatus?id='+result[1])
                    if status[5] in ('FINISHED','ERROR-FAILED','ABORTED'): break
                    time.sleep(.5)
                if status[5] != 'FINISHED': raise RuntimeError('Engine smoke scan did not finish')
                if not get('/scaneventresults?id='+result[1]): raise RuntimeError('Engine produced no seed evidence')
            except Exception:
                log.flush()
                print((Path(tmp)/'startup.log').read_text(errors='replace'))
                raise
            finally:
                subprocess.run(['taskkill','/PID',str(p.pid),'/T','/F'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0), timeout=10)
                p.wait(timeout=10)
    print('Portable engine: readiness, scan, evidence and shutdown passed.')
