# SPECTRA Architecture

## Core flow
Input/Case → Orchestrator → Connector selection → Providers/Engines → Normalizer → Deduplicator → Correlator → Confidence → Evidence Store → Graph → Risk/Remediation → Report.

## Layers
1. GUI — investigation/cases/graph/reports/connectors/settings/logs.
2. Case service — local case lifecycle and authorization metadata.
3. Orchestrator — source selection, jobs, progress, cancellation, pivot limits.
4. Connector SDK — stable adapter interface for SpiderFoot/Shodan/HIBP/etc.
5. Normalized data model — typed entities, relationships and provenance.
6. Correlation engine — dedupe, pivots, confidence and contradictions.
7. Evidence store — source records, timestamps and raw evidence references.
8. Reporting — client-friendly HTML/PDF.
9. Runtime manager — bundled engines/process readiness/recovery/shutdown.

## Security invariants
- Secrets never enter Git.
- Plaintext passwords are never persisted.
- Provider failures are isolated.
- Public/authorized defensive scope only.
- Unknown-person biometric identification is out of scope.
