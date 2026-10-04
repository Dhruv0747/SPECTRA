SPECTRA — Digital Exposure & OSINT Auditor
Powered by Dhruv Kaushik

v0.3 INVESTIGATION WORKSPACE
- Dark Windows dashboard with Investigation, Cases, Graph, Reports, Connectors,
  Settings and Logs views.
- Create/open/save/archive/import/export cases with client and assessment scope.
- Multiple targets with automatic classification and manual overrides.
- Background scans, elapsed time, source state, warnings and cancellation.
- Evidence with timestamps, references, confidence and pivot paths; deduplication
  preserves observations. Graph supports pan, zoom and confidence filtering.
- Keyless DNS, InternetDB and public GitHub profile lookups; configured Shodan
  and HIBP account APIs. Provider errors never count as clean results.
- Bundled SpiderFoot v4.0 with its own embedded Python runtime. SPECTRA starts,
  checks, polls, ingests, cancels and shuts down the engine it owns.
- Local image SHA-256, aHash/dHash/pHash, dimensions, EXIF and duplicate/similarity
  comparison among images in the same scan. Similarity is not identity evidence.
- Password range checks transmit only a SHA-1 prefix and retain no password/hash.
- HTML client report with coverage, observations, relationships and remediation.
  Print the report from a browser to save a PDF.
- Developer controls for sources, timeout, retry and pivot depth. No artificial
  case or finding count caps; actual resources and provider quotas still apply.

RUN THE PORTABLE BUILD
Extract the entire SPECTRA-Windows-Portable.zip, then double-click SPECTRA.exe.
Keep _internal and tools beside the EXE. No system Python is required.
Create a case with the authorized scope, add targets and run the investigation.
Use Settings for API keys and source selection. SpiderFoot uses loopback :5001.
An already-running configured SpiderFoot server is reused and is never killed.

BUILD FROM SOURCE (WINDOWS)
Python 3.13 with Tk is used for the GUI. Run build_windows.bat.
The build installs pinned GUI requirements, runs tests, downloads checksum-pinned
SpiderFoot/Python archives, assembles the engine, verifies GUI startup and a real
storage-only engine scan, then emits:
  dist/SPECTRA-v0.3/SPECTRA.exe
  dist/SPECTRA-Windows-Portable.zip
  dist/SPECTRA-Windows-Portable.zip.sha256
The build-time pip bootstrap is checksum pinned. If upstream changes it, the
build fails rather than executing changed bytes; review before updating the pin.
For source development: pip install -r requirements.txt, then run_spectra.pyw.
Tests: python -m unittest discover -s tests -v

DATA AND SECRETS
Cases, settings, reports, cache and engine data remain inside the application
folder. Settings currently store API keys in plaintext locally; protect this
folder. They are excluded from Git, release bundles and case/report exports.
Case exports and reports contain assessment data; share them deliberately.
Cancellation cannot interrupt an in-flight HTTP request; it takes effect at the
next timeout/response and sends a stop request for a running SpiderFoot scan.

KNOWN LIMITATIONS / RELEASE STATUS
This is a development release, not a claim that the entire master roadmap is
complete. Live paid API calls need user keys. SpiderFoot modules depend on their
upstreams and may require keys or fail independently; the entire module catalog
has not been validated. Broad web/reverse-image occurrence search is not included.
Perceptual matches need manual review. Confidence is conservative and there is no
advanced cross-provider identity/contradiction engine. No unknown-person face
identification or private-account bypass is implemented. The exposure indicator
is a documented heuristic, not a probability or a clean bill of health.
Relocated Windows smoke tests are run; clean-VM acceptance remains outstanding.
See ROADMAP.md and THIRD_PARTY_NOTICES.md for scope and bundled components.
