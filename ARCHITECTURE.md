# SPECTRA architecture

The Windows desktop app is a local evidence workspace. It does not require a browser or terminal for normal operation.

- `spectra/app.py`: Tk dashboard, navigation, case actions, graph, settings, report and password dialogs. Background workers emit events into a queue; only the UI thread touches Tk and case state.
- `spectra/core.py`: validated targets, atomic JSON storage, stable finding/entity IDs, provenance-preserving deduplication, conservative confidence, exposure indicator and escaped offline HTML reports.
- `spectra/providers.py`: passive provider adapters, local image analysis, password range checks, sequential cancellable orchestration and an owned SpiderFoot process manager.
- `scripts/build_spiderfoot.py`: checksum-verified upstream source plus relocatable embedded CPython. Upstream engine source is preserved with its license; dependency adaptations are recorded in the bundle.
- `scripts/build_windows.py`: tests, isolated staging, PyInstaller, notices, GUI smoke, relocated engine smoke, ZIP and SHA-256. Local cases/settings are never copied to staging.
- `scripts/smoke_engine.py`: real readiness, storage-only loopback scan, evidence retrieval and process-tree cleanup.

## Data lifecycle

A case stores ID, name, client, authorization scope, timestamps, targets, findings, scans and report references. Findings contain typed subject/object entities, an explicit relationship, severity/confidence, remediation and a list of independent observations. Each observation carries provider, timestamp, reference, original target, pivot path and raw evidence. Deduplication merges observations rather than dropping their sources. Imported cases receive a new UUID.

Workers never write cases or Tk widgets. UI queue processing applies observations and saves atomically; scan status is recorded separately from findings. Provider failures are coverage warnings, not evidence of no exposure. Interrupted scans retain partial results.

## Runtime boundaries

SPECTRA launches only the bundled engine on loopback, redirects its data/cache/logs into the portable folder, and only stops processes it owns. Existing configured servers are reused. HTTP calls use finite timeouts; stop prevents queued work and requests SpiderFoot cancellation. The SpiderFoot integration uses upstream ping/startscan/scanstatus/scaneventresults/stopscan endpoints. It does not merely open the web UI.

## Security and limits

Passwords and full password hashes never enter cases, reports or logs. API credentials are currently local plaintext settings and never included in artifacts or exports. Reports escape all case/evidence text. No result-count or case-count cap is imposed. Provider quotas, local resources and HTTP timeouts still apply. Username equality and engine events are never treated as verified personal identity.
