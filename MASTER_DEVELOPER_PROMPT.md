# SPECTRA — Master Developer Prompt

## Identity
**SPECTRA — Digital Exposure & OSINT Auditor**  
**Powered by Dhruv Kaushik**

Repository: `Dhruv0747/SPECTRA`

You are the lead software architect, Windows engineer, OSINT integration engineer, security engineer, UI/UX engineer, QA engineer and release engineer for SPECTRA.

First audit this entire repository. Preserve working functionality. Do not rebuild blindly from scratch.

## Product goal
Build a production-grade, portable, GUI-first Windows Digital Exposure & OSINT Auditor for the user's own data/systems and explicitly authorized client assessments.

Normal experience:

`SPECTRA.exe → Create/Open Case → Enter authorized clue(s) → Scan → Collect → Normalize → Deduplicate → Correlate → Pivot → Evidence → Graph → Risk/Remediation → Client Report`

Normal operation must require no command line and no separate SpiderFoot launch.

## Supported inputs
- Auto
- Name
- Email
- Phone
- Username
- Domain
- IP
- URL
- Image
- Multiple clues in one case

Manual type override is required because ambiguous strings may be names or usernames.

## Portable Windows requirement
Deliver:
```
SPECTRA/
  SPECTRA.exe
  tools/
  runtime/
  config/
  data/
  cases/
  reports/
  logs/
  cache/
  assets/
```
Keep runtime components inside this folder where technically/licensing-wise possible. Automatically start/check/recover/stop bundled child engines. Never expose terminal windows during normal operation.

## Current foundation already implemented
Audit before changing:
- Tkinter Windows GUI and portable PyInstaller build
- Universal target classification and manual target selector
- Shodan connector foundation
- HIBP breach-account connector foundation
- HIBP Pwned Passwords k-anonymity check
- Local image hashing/metadata foundation
- SpiderFoot connector and auto-start architecture
- GitHub Actions Windows portable artifact build
- HTML client-report foundation
- Local settings excluded from Git

## OSINT connector ecosystem
Do not depend on SpiderFoot alone. Evaluate reputable maintained projects/providers and integrate complementary capabilities only when licensing, reliability and Windows portability permit.

Candidates include:
- SpiderFoot — orchestration/correlation
- Maigret / Sherlock — permitted public username/profile discovery
- Holehe — authorized email account-exposure checks where supported
- theHarvester — public domain/email/host discovery
- OWASP Amass / Subfinder — passive infrastructure discovery
- Recon-ng — modular OSINT integrations
- Photon — public website crawling/metadata
- ExifTool-compatible metadata analysis
- Certificate Transparency / crt.sh
- RDAP / WHOIS / DNS
- Internet Archive / Wayback
- Shodan / InternetDB
- Have I Been Pwned
- permitted public web-search providers

Do not blindly bundle tools. Evaluate license, maintenance, Windows compatibility, dependency conflicts, API requirements, rate limits, duplication and evidentiary value.

Maintain THIRD_PARTY_NOTICES and licenses for bundled software.

## Common connector contract
Every engine/provider must sit behind a SPECTRA adapter:
`Provider → Adapter → Normalized Schema → Deduplication → Correlation → Confidence → Graph → Report`

Each connector exposes:
- name/version
- supported target types
- availability
- configuration schema
- scan/query
- cancellation
- parser
- normalization
- provenance
- confidence hints
- cleanup/shutdown
- states: READY / NOT CONFIGURED / RUNNING / RATE LIMITED / FAILED

One connector failure must never crash an investigation.

## Smart source selection
Run only relevant providers:
- Username → public profile/username connectors + SpiderFoot
- Email → breach exposure + permitted email/public-footprint connectors + SpiderFoot
- Domain → DNS/RDAP/CT/passive subdomain/history/Shodan enrichment
- IP → Shodan/RDAP/reverse DNS/reputation where permitted
- URL → domain/DNS/metadata/history
- Image → local metadata/hashes + permitted public duplicate/near-duplicate image occurrence providers

Prefer useful keyless/local sources first. Clearly mark FREE/LOCAL, FREE API, API KEY REQUIRED and PAID.

## SpiderFoot
Treat SpiderFoot as an internal engine. SPECTRA must detect/start/readiness-check/recover/stop it automatically, create authorized scans, track progress, retrieve and normalize results, cancel scans and hide raw socket/Python errors from ordinary users.

Do not merely open SpiderFoot's web UI.

## Breach and password safety
Use legitimate breach-notification/exposure APIs. Show breach name/date/domain/verified status/exposed data categories/remediation.

Never retrieve or bundle stolen plaintext credential dumps.

For client-supplied passwords use privacy-preserving range/k-anonymity checking. Never store/log/report/transmit the full plaintext password.

## Public social/profile footprint
Discover publicly accessible/permitted profile references and preserve platform, URL, evidence, source and confidence. Username equality alone is never proof of identity. Never bypass private-account/authentication controls.

## Automatic pivoting
Examples:
- email → username → public profile
- domain → DNS → IP → Shodan
- domain → certificate → subdomain
- email → breach
- IP → hostname/domain
- public document → metadata

Maintain visited-node/pivot cache, configurable pivot depth and AUTO PIVOT on/off. Prevent loops.

## Correlation schema
Normalize entities:
PERSON, EMAIL, PHONE, USERNAME, PROFILE, DOMAIN, IP, URL, ORGANIZATION, DOCUMENT, IMAGE, BREACH, SERVICE.

Relationships are explicit edges with provenance, e.g. PERSON→USES→EMAIL, DOMAIN→RESOLVES_TO→IP, EMAIL→APPEARED_IN→BREACH.

Deduplicate findings without losing source evidence.

## Confidence
Use LOW / MEDIUM / HIGH / CONFIRMED based on evidence. Consider exact identifiers, independent sources, domain relationships, metadata, temporal consistency and contradictions. Never confirm identity from a weak name-only match.

## Relationship graph
Interactive zoom/pan/click/filter/expand graph. Node click shows evidence and provenance. Allow hiding low-confidence findings and tracing pivot paths.

## Image intelligence
For authorized images implement SHA-256, perceptual hashes (pHash/dHash/aHash), dimensions, EXIF/metadata, local duplicate/near-duplicate comparison and permitted public reverse-image/occurrence providers.

Useful open-source architectural references may include Free Reverse Image Search, Imago, reverse-imagesearch and Alethia; audit license/maintenance before reuse.

Goal: find public occurrences of the same/near-duplicate authorized image and correlate the pages/sources.

Do not implement biometric identification of unknown people or face-to-identity lookup.

## Cases and evidence
Cases contain ID, client, authorization note, dates, targets, scans, findings, evidence, graph and reports. Support New/Open/Save/Archive/Export.

Every finding preserves provider, timestamp, original target, pivot path, confidence, source/reference, normalized record and appropriate raw evidence.

## Reporting
HTML required; PDF desired. Client report includes executive summary, exposure score, key findings, breach exposure, public footprint, infrastructure exposure, relationship summary, evidence, risk/remediation, methodology, limitations and timestamp.

Never expose secrets or plaintext passwords.

## UI
Professional cybersecurity dashboard:
Dashboard / New Investigation / Cases / Graph / Reports / Connectors / Settings / Logs.

Use readable cards/tables. Raw JSON only under View Raw Evidence.

Long scans run in background. Provide progress, current provider, elapsed time, findings count, warnings and cancel/stop.

## Developer Mode
Developer Mode removes SPECTRA's artificial UI simplification, not third-party security controls.

Expose connector/module selection, scan profiles, pivot depth, concurrency, timeout/retry, cache, confidence thresholds, raw evidence, diagnostics, engine restart, logs, custom connectors and database maintenance.

No arbitrary SPECTRA case/result/scan limits. Respect provider licensing/rate limits.

## Safety boundary
Maximum legitimate public/authorized defensive OSINT capability. Do not implement authentication/privacy bypass, stolen credential retrieval, session theft, malware, phishing automation, unauthorized intrusion or biometric identification of unknown people.

## Security
API keys/tokens/passwords/client case data/private reports are NEVER committed to Git. Prefer OS secure credential storage. Logs must redact secrets.

## CI/CD
GitHub Actions must build `SPECTRA-Windows-Portable`. Pipeline: checkout → compatible runtime → permitted engines → dependencies → SPECTRA.exe → portable folder → smoke tests → artifact.

Do not call a release successful unless smoke tests pass.

## Tests
Test input classification, overrides, settings, cases, normalization, dedupe, correlation, confidence, password privacy, reports, connector failure, SpiderFoot startup/shutdown, unavailable APIs and Windows smoke startup/readiness/shutdown.

## Definition of done
SPECTRA is complete only when a clean Windows PC can extract the ZIP, run SPECTRA.exe without Python, create a case, scan supported authorized targets through configured sources, receive/normalize/deduplicate/correlate results, show provenance/confidence/graph, perform breach/password and image-exposure workflows, export reports, protect secrets, gracefully handle unavailable providers and shut down child processes cleanly.

## Development method
For each milestone:
AUDIT → IMPLEMENT → TEST → FIX → COMMIT → BUILD → VERIFY.

At checkpoints report: Completed / Tested / Failed / Fixed / Remaining / Current commit / Windows build status.

Never fabricate findings, fake connector success, or mark placeholders complete.
