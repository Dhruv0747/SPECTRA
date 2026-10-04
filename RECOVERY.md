# SPECTRA Disaster Recovery

This repository is the canonical source for rebuilding SPECTRA.

## If the original PC/project folder is lost
1. Install Git on a Windows development PC.
2. Clone this repository.
3. Read `MASTER_DEVELOPER_PROMPT.md`, `ARCHITECTURE.md`, `ROADMAP.md` and `README.md`.
4. Do **not** expect API keys, passwords, client cases or private reports in Git; they are intentionally excluded.
5. Use GitHub Actions to rebuild the portable Windows artifact, or follow the local build instructions.
6. Restore any separately backed-up local configuration/cases only if authorized and available.

## Canonical items that MUST stay in Git
- application source
- connector source
- tests
- schemas
- report templates
- safe example configuration
- build scripts
- GitHub Actions
- architecture/docs
- migration scripts
- dependency manifests/lock files
- THIRD_PARTY_NOTICES/licenses
- changelog

## Items that MUST NOT be committed
- API keys/tokens
- passwords
- client case data
- private reports
- secret settings
- credential dumps
- runtime logs containing client identifiers

## Release recovery
Every stable release should have:
- Git tag
- changelog entry
- successful Windows CI
- portable artifact/release ZIP
- SHA-256 checksum

A fresh developer/AI should be able to understand the project from the repository without access to the original development machine.
