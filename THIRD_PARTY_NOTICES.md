# Third-party notices

SPECTRA v0.3 bundles these independently licensed components. Preserve the accompanying notices when redistributing.

- **SpiderFoot v4.0** — https://github.com/smicallef/spiderfoot/tree/v4.0 — GPL-2.0 license as supplied upstream. Complete unmodified engine source, LICENSE and upstream attribution are included under `tools/spiderfoot`. SPECTRA interacts through its local HTTP interface. Runtime/dependency adaptations are listed in `SPECTRA-MODIFICATIONS.txt` and `requirements-spectra.lock` inside that directory.
- **CPython 3.11.9 Windows embedded runtime** — https://www.python.org/downloads/release/python-3119/ — Python license included in `tools/spiderfoot/runtime/LICENSE.txt`. Used only by the engine.
- **CPython and Tcl/Tk for the GUI** — versions supplied by the build interpreter; license files copied to `licenses` where present. Python/Tk are packaged by PyInstaller.
- **Pillow 12.3.0** — https://github.com/python-pillow/Pillow — MIT-CMU; distribution licenses copied into `licenses/Pillow`.
- **PyInstaller 6.20.0** — https://github.com/pyinstaller/pyinstaller — GPL with bootloader distribution exception; notices copied into `licenses/PyInstaller`.
- **Engine dependencies** — exact versions are pinned in `requirements-spiderfoot.lock`; their distribution metadata and license files remain in the embedded runtime's `Lib/site-packages`. SPECTRA updates upstream's old PyYAML, cryptography, pyOpenSSL and lxml constraints for the tested Windows environment. This is not a claim that all third-party modules have been audited or validated.

Google Public DNS, GitHub, Shodan/InternetDB and Have I Been Pwned are externally accessed APIs, not bundled software. Their availability, subscriptions and rate limits apply. No credential corpus is bundled.

Other projects in MASTER_DEVELOPER_PROMPT.md are candidates, not implemented or bundled integrations.
