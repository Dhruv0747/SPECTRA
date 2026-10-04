"""Opt-in live acceptance: actual Passive profile with synthetic identity clues."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from spectra.core import DEFAULTS, target
from spectra.providers import Scanner, Engine, request_json


def main():
    bundle = Path(sys.argv[1]).resolve()
    engine = bundle/'tools/spiderfoot'
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        port=sock.getsockname()[1]
    base=f'http://127.0.0.1:{port}'
    with tempfile.TemporaryDirectory(prefix='spectra-live-acceptance-') as folder:
        env=os.environ.copy()
        for key,name in [('SPIDERFOOT_DATA','data'),('SPIDERFOOT_CACHE','cache'),('SPIDERFOOT_LOGS','logs')]: env[key]=str(Path(folder)/name)
        with (Path(folder)/'engine.log').open('w') as log:
            proc=subprocess.Popen([str(engine/'runtime/python.exe'),str(engine/'sf.py'),'-l',f'127.0.0.1:{port}'],cwd=engine,env=env,stdout=log,stderr=log,creationflags=subprocess.CREATE_NO_WINDOW)
            try:
                for _ in range(50):
                    if proc.poll() is not None: raise RuntimeError('Engine exited')
                    try:
                        if request_json(base+'/ping',timeout=1)[0]=='SUCCESS': break
                    except Exception: time.sleep(.5)
                else: raise RuntimeError('Engine readiness timed out')
                for value, kind in [('Jane Doe','Name'),('+12025550100','Phone'),('jane@example.com','Email')]:
                    cancel=threading.Event()
                    events=[]
                    def emit(k,v):
                        events.append((k,v))
                        if k=='provider' and v=='SpiderFoot · RUNNING': cancel.set()
                    guard=threading.Timer(40,cancel.set)
                    guard.start()
                    try:
                        scanner=Scanner(dict(DEFAULTS,spiderfoot_url=base,retries=0),emit,cancel,Engine(bundle))
                        t=target(value,kind)
                        scanner.spiderfoot(t,[t])
                    finally: guard.cancel()
                    scans=[v for k,v in events if k=='engine_scan']
                    assert scans,kind+' did not start'
                    states=[v for k,v in events if k=='provider']
                    assert any(v.endswith(('RUNNING','FINISHED')) for v in states),kind+' did not progress'
                    scanid=scans[0]['id']
                    for _ in range(60):
                        status=request_json(base+'/scanstatus?'+urllib.parse.urlencode({'id':scanid}),timeout=5)
                        if status[5] in ('ABORTED','FINISHED'): break
                        time.sleep(.5)
                    assert status[5] in ('ABORTED','FINISHED'),kind+' did not stop: '+str(status[5])
                    warnings=[v for k,v in events if k=='warning']
                    assert not warnings,warnings
                    findings=sum(k=='finding' for k,v in events)
                    print(kind+': started, progressed, '+status[5]+f'; {findings} evidence observations',flush=True)
            finally:
                subprocess.run(['taskkill','/PID',str(proc.pid),'/T','/F'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
                proc.wait(timeout=10)
    print('Real default-profile startup/progress/cancellation acceptance passed.',flush=True)


if __name__=='__main__': main()
