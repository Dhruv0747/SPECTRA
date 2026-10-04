"""Build and smoke-test the standalone Windows GUI; never copy local secrets."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile
import importlib.metadata
from build_spiderfoot import prepare_engine
from smoke_engine import smoke_engine


def main():
    if sys.platform != "win32":
        raise SystemExit("Run this build on Windows.")
    root = Path(__file__).resolve().parent.parent
    subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-v'], cwd=root, check=True)
    engine = prepare_engine()
    # A fresh staging directory prevents previous builds or user data entering ZIPs.
    with tempfile.TemporaryDirectory(prefix="spectra-build-") as staging:
        staging = Path(staging)
        subprocess.run([
            sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
            "--windowed", "--name", "SPECTRA", "--distpath", str(staging / "dist"),
            "--workpath", str(staging / "work"), "--specpath", str(staging),
            str(root / "run_spectra.pyw"),
        ], cwd=root, check=True)
        bundle = staging / "dist" / "SPECTRA"
        for folder in ("config", "data", "cases", "reports", "logs", "cache", "assets", "tools", "runtime"):
            (bundle / folder).mkdir()
        shutil.copy2(root / "config/settings.example.json", bundle / "config")
        for name in ("README.txt", "THIRD_PARTY_NOTICES.md"):
            shutil.copy2(root / name, bundle)
        shutil.copytree(engine, bundle / 'tools/spiderfoot', ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.git', '.github'))
        licenses = bundle / 'licenses'
        licenses.mkdir()
        for package in ('Pillow', 'PyInstaller'):
            dist = importlib.metadata.distribution(package)
            for file in dist.files or []:
                if 'license' in str(file).lower() or 'copying' in str(file).lower():
                    source = Path(dist.locate_file(file))
                    if source.is_file():
                        dest = licenses / package / str(file)
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(source, dest)
        for source in (Path(sys.base_prefix) / 'LICENSE.txt', Path(sys.base_prefix) / 'tcl/tcl8.6/license.terms', Path(sys.base_prefix) / 'tcl/tk8.6/license.terms'):
            if source.is_file(): shutil.copy2(source, licenses / (source.parent.name + '-' + source.name))
        if (root / 'LICENSE').exists(): shutil.copy2(root / 'LICENSE', bundle / 'LICENSE')
        # Use a different working directory and no developer Python on PATH.
        env = os.environ.copy()
        env["PATH"] = str(Path(os.environ["SystemRoot"]) / "System32")
        subprocess.run([str(bundle / "SPECTRA.exe"), "--smoke-test"],
                       cwd=staging, env=env, check=True, timeout=30)
        smoke_engine(bundle)
        output = root / "dist"
        output.mkdir(exist_ok=True)
        archive = output / "SPECTRA-Windows-Portable.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
            for path in sorted(bundle.rglob("*")):
                z.write(path, path.relative_to(bundle.parent))
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        archive.with_suffix(".zip.sha256").write_text(
            f"{checksum}  {archive.name}\n", encoding="ascii")
        # Keep an immediately runnable copy too, without replacing existing user data.
        destination = output / "SPECTRA-v0.3"
        shutil.copytree(bundle, destination, dirs_exist_ok=True)
        print(f"Smoke test passed. Portable GUI: {archive}")


if __name__ == "__main__":
    main()
