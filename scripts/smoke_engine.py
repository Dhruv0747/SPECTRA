"""Verify a relocated engine with a storage-only loopback scan; no target probes."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
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
        # Exercise the app's actual profile selection without enabling hundreds
        # of external lookups in a packaging test. The real upstream startscan
        # handler selects the storage module through its case-sensitive group.
        launcher = Path(tmp) / 'profile_smoke.py'
        launcher.write_text('''import runpy, sys, sfwebui
original_init = sfwebui.SpiderFootWebUi.__init__
def isolated_init(self, *args, **kwargs):
    original_init(self, *args, **kwargs)
    for name, config in self.config['__modules__'].items():
        config['group'] = ['Passive'] if name == 'sfp__stor_db' else []
sfwebui.SpiderFootWebUi.__init__ = isolated_init
if __name__ == '__main__':
    script = sys.argv.pop(1)
    sys.argv[0] = script
    runpy.run_path(script, run_name='__main__')
''', encoding='utf-8')
        with (Path(tmp)/'startup.log').open('w') as log:
            p = subprocess.Popen([str(runtime), str(launcher), str(engine/'sf.py'), '-l', f'127.0.0.1:{port}'], cwd=engine, env=env,
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
                sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
                from spectra.core import DEFAULTS, target
                from spectra.providers import Scanner, Engine
                events = []
                scanner = Scanner(dict(DEFAULTS, spiderfoot_url=base, connectors=[], retries=0),
                                  lambda k, v: events.append((k, v)), threading.Event(), Engine(bundle))
                for value, kind in [('Jane Doe', 'Name'), ('+12025550100', 'Phone'), ('jane@example.com', 'Email')]:
                    before = sum(k == 'finding' for k, _ in events)
                    t = target(value, kind)
                    scanner.spiderfoot(t, [t])
                    if sum(k == 'finding' for k, _ in events) <= before:
                        raise RuntimeError(kind + ' scan returned no seed evidence')
            except Exception:
                log.flush()
                print((Path(tmp)/'startup.log').read_text(errors='replace'))
                raise
            finally:
                subprocess.run(['taskkill','/PID',str(p.pid),'/T','/F'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0), timeout=10)
                p.wait(timeout=10)
    print('Portable engine: default Passive profile, name/phone/email scans, evidence and shutdown passed.')
