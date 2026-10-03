SPECTRA — Digital Exposure & OSINT Auditor
Powered by Dhruv Kaushik

FIRST MVP
1. Windows graphical UI (Tkinter).
2. Universal input classification: name/email/phone/username/domain/IP.
3. Shodan IP lookup when an API key is configured.
4. Privacy-preserving HIBP Pwned Passwords check: only a SHA-1 prefix is sent; plaintext is not stored.
5. Image local hashing/metadata foundation; no face identification.
6. SpiderFoot local connector setting.
7. Local findings dashboard and HTML client report.

RUN
- Install Python 3.11+ for Windows with Tk support.
- Double-click run_spectra.pyw.
- Settings are stored only in config/settings.json and are ignored by Git.

PORTABLE PACKAGING
The project is intentionally self-contained in this SPECTRA folder. A later Windows build can bundle Python into SPECTRA.exe using PyInstaller, while keeping config/data/reports/tools beside it.

SECURITY SCOPE
Use only on your own systems/data or with explicit authorization. SPECTRA does not retrieve stolen plaintext credentials, bypass private social accounts, or identify unknown people from facial images.
