"""Assemble a relocatable SpiderFoot source + embedded Python bundle on Windows."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DOWNLOADS = {
    'python.zip': ('https://www.python.org/ftp/python/3.11.9/python-3.11.9-embed-amd64.zip', '009d6bf7e3b2ddca3d784fa09f90fe54336d5b60f0e0f305c37f400bf83cfd3b'),
    'spiderfoot.zip': ('https://github.com/smicallef/spiderfoot/archive/refs/tags/v4.0.zip', 'ed82f28e29c860a2e997e885eca11368a07a7b0c924fcafd5b66b9ecd095b8a1'),
    'get-pip.py': ('https://bootstrap.pypa.io/get-pip.py', 'fb24e693bab954209a063d90953621412ccad4a500905a726286e038f508ddf6'),
}


def download(name):
    url, expected = DOWNLOADS[name]
    folder = ROOT/'build/downloads'
    folder.mkdir(parents=True, exist_ok=True)
    path = folder/name
    if not path.exists(): urllib.request.urlretrieve(url, path)
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise RuntimeError(f'{name} checksum mismatch; review upstream before updating the pinned digest.')
    return path


def prepare_engine():
    if sys.platform != 'win32': raise RuntimeError('Windows build required')
    bundle = ROOT/'build/engine-bundle/spiderfoot'
    lock = ROOT/'requirements-spiderfoot.lock'
    expected = hashlib.sha256(lock.read_bytes()).hexdigest()
    marker = bundle/'SPECTRA-BUNDLE.txt'
    if marker.exists() and marker.read_text().strip() == expected: return bundle
    bundle.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(download('spiderfoot.zip')) as z:
        for member in z.infolist():
            relative = Path(*Path(member.filename).parts[1:])
            if not relative.parts: continue
            dest = (bundle/relative).resolve()
            if not dest.is_relative_to(bundle.resolve()): raise RuntimeError('Unsafe archive member')
            if member.is_dir(): dest.mkdir(parents=True, exist_ok=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(z.read(member))
    runtime = bundle/'runtime'
    runtime.mkdir(exist_ok=True)
    with zipfile.ZipFile(download('python.zip')) as z: z.extractall(runtime)
    (runtime/'python311._pth').write_text('python311.zip\n.\n..\nLib/site-packages\nimport site\n', encoding='ascii')
    exe = runtime/'python.exe'
    subprocess.run([str(exe), str(download('get-pip.py')), 'pip==24.3.1', 'setuptools==69.5.1', 'wheel==0.48.0'], check=True)
    # Embedded Python omits cwd; legacy pure-Python setup scripts require it.
    customize = runtime/'Lib/site-packages/sitecustomize.py'
    customize.write_text('import os, sys; sys.path.insert(0, os.getcwd())\n', encoding='ascii')
    subprocess.run([str(exe), '-m', 'pip', 'install', '-r', str(lock)], check=True)
    customize.write_text('# Build-time cwd injection removed for runtime.\n', encoding='ascii')
    shutil.copy2(lock, bundle/'requirements-spectra.lock')
    (bundle/'SPECTRA-MODIFICATIONS.txt').write_text(
        'SpiderFoot v4.0 source is unmodified. SPECTRA supplies an embedded CPython 3.11.9 runtime.\n'
        'Dependency overrides: PyYAML 6.0.2, cryptography 50.0.2, pyOpenSSL 26.4.0, lxml 6.1.3.\n'
        'Exact direct/transitive versions are in requirements-spectra.lock.\n'
        'SPECTRA binds its owned server to loopback and redirects data/cache/logs into the portable folder.\n'
        'Upstream: https://github.com/smicallef/spiderfoot/tree/v4.0\n', encoding='utf-8')
    marker.write_text(expected, encoding='ascii')
    return bundle


if __name__ == '__main__': print(prepare_engine())
