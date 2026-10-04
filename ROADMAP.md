# SPECTRA status and remaining roadmap

## Implemented in v0.3

- Desktop workspace and functional case lifecycle with import/export/archive.
- Background scans, progress/status, cancellation, retained evidence and report export.
- Typed entities/relationships, source timestamps, pivot paths and deduplication.
- DNS-derived IP pivots with visited-target suppression and adjustable depth.
- Keyless DNS, InternetDB, public GitHub profiles; configured HIBP/Shodan.
- Bundled SpiderFoot source/runtime, startup/readiness, scan polling, evidence ingestion, stop and owned process shutdown.
- Image hashes/metadata and same-run duplicate/similarity candidates.
- HIBP password range privacy, HTML reports, pan/zoom graph and evidence filters.
- Windows build, offline unit/GUI tests and a relocated engine smoke gate.

## Still outstanding before a production-complete claim

- Clean Windows VM acceptance and manual visual/accessibility QA.
- Live authenticated HIBP/Shodan acceptance using owner-provided keys.
- Validation of individual SpiderFoot modules against their evolving sources.
- Stronger encrypted local credential storage, cache policies and large-case indexing.
- Advanced multi-provider correlation, contradiction handling and user review workflow.
- Additional explicitly supported profile/public-web/reverse-image occurrence providers.
- A native PDF exporter (browser print is supported now).
- Full custom-connector SDK and detailed per-module UI configuration.

The master developer prompt remains the longer-term product specification. No unsupported feature is represented as complete.
