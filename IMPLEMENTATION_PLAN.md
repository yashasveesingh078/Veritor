# Implementation Plan

The backend scan pipeline, API endpoints (POST /api/v1/scans, GET status, report, findings,
files, diffs), retrieval and comparison orchestration, generated artifact intelligence,
static AST security scanning, provenance checks, deterministic risk scoring, and the Ollama AI
investigator (qwen2.5-coder:7b) are implemented and tested.

## Goal

Given a package and version on npm or PyPI, compare the published artifact with
its source repository, explain each difference with evidence, and flag
modifications that cannot be explained or that add risky behaviour.

## Principles

- **Evidence first.** Deterministic code analysis produces the findings. Models
  sort and interpret them afterwards.
- **Models cannot clear hard evidence.** A model may not downgrade a finding
  such as an untraceable new install script.
- **Package contents are untrusted.** Never install or execute them. Pass them
  to models as delimited data, never as instructions.
- **Everything runs locally.** Models run through Ollama, one at a time, to fit
  a 16 GB laptop.
- **Report uncertainty.** "Could not verify" is a separate result from "clean".

## Phases

### Phase 0: Scaffold (done)

Repository structure, placeholder frontend, FastAPI health endpoint, Python
configuration, CI, license and docs.

### API foundation (done)

Modular routes, settings, logging, schemas, error handling, CORS, `GET /health`,
and scan orchestration with background tasks, real status progression, report,
findings, file inventory, and diff endpoints.

### Phase 1: Fetch artifacts (done)

- Done for npm: `PackageAdapter` interface, exact-version metadata, and tarball
  download verified against registry hashes.
- Done: safe extraction and file inventory for npm and GitHub archives preventing
  symlink traversal, path escaping, and archive bombs.
- Done: compare registry metadata with the `package.json` inside the tarball to
  detect metadata spoofing or hidden install scripts.
- To do: PyPI adapter.

### Phase 2: Locate source (done)

- Done for GitHub: find the repository from package metadata, match the version
  to a commit using recorded commits, tags, and heuristics, record the method and
  confidence, and download the archive for that exact commit.
- A version with no established match is `UNCERTAIN`. No default branch is ever
  used in its place.
- To do: support repositories outside GitHub (GitLab, Bitbucket).

### Phase 3: Compare & Generated Artifact Intelligence (done)

- Done: compare inventories by SHA-256, with per-file JSON evidence and text
  diffs. Each file is identical, added, removed, modified, binary-different or
  renamed. Renames need an exact, unambiguous content match.
- Done: `artifact_classifier.py` analyzes `package.json`, `tsconfig.json`, bundler
  configs, entry points, source maps, counterparts, token similarity, and affirmative
  suspicious indicators.
- Classifies files strictly by evidence into:
  - `LIKELY_GENERATED`: supported by build pipeline and source relationship evidence.
  - `SUSPICIOUS`: deceptive source maps, unlinked execution in install scripts,
    obfuscated packing, or unexpected executable bits.
  - `UNCERTAIN`: when evidence is inconclusive. Never blindly whitelists `dist/`,
    `build/`, or `lib/`.
- Done: confirm the `package.json` at the matched commit has the same name and
  version, and report any disagreement as a warning.

### Phase 4: Static Security Scanner (done)

- Done: AST-based scanning for JavaScript and TypeScript (supporting JS, MJS, CJS,
  JSX, TS, MTS, CTS, TSX) using Tree-Sitter without ever executing untrusted code.
- Done: analyze added and modified files across 7 primary categories:
  1. `eval()` and `new Function()` dynamic execution (`EXEC-001` through `EXEC-005`).
  2. `child_process` execution and dangerous shell invocation (`PROC-001` through `PROC-005`).
  3. `process.env` access, credential-like variables, and whole-env dumping (`ENV-001` through `ENV-003`).
  4. Unexpected outbound network calls, data collectors, and public IP calls (`NET-001` through `NET-003`).
  5. Base64 runtime decoding, character code generation, and obfuscator names (`OBF-001` through `OBF-004`).
  6. Suspicious filesystem operations on credentials or startup files (`FS-001`, `FS-002`).
  7. Lifecycle scripts (`preinstall`, `install`, `postinstall`) tracked vs repository (`LIFE-001` through `LIFE-007`).
- Done: multi-signal correlation (`CORR-001` through `CORR-005`) for credentials + network, decoding + execution, network + execution, obfuscation + sensitive API, and sensitive behavior at install.
- Done: contract validation: every finding includes `rule_id`, `path`, `line`, `severity`, `evidence`, `explanation`, `confidence`, and `recommended_action`.
- Done: source-to-package differential scanning: pre-existing source patterns are separated so ordinary API usage is never treated as malicious.
- Done: integration with artifact intelligence (suspicious artifacts elevate finding confidence).
- Done: npm provenance verification with Sigstore against the downloaded tarball.
- Done: deterministic risk scoring traced to specific factors.

### Phase 5: AI Investigator (done)

- Connects to Ollama `qwen2.5-coder:7b` to explain findings with structured JSON output.
- Real deterministic findings and code excerpts supplied; model never invents evidence
  and never overrides risk scores.
- Graceful fallback when Ollama is offline or unavailable.

### Phase 6: Scan Orchestration & CI/CD (done)

- Endpoints implemented: `POST /api/v1/scans`, `GET /api/v1/scans/{id}`, `/report`,
  `/findings`, `/files`, `/diff`.
- Production-grade GitHub Actions CI/CD workflows:
  - CI: Python setup, linting (Ruff), type check (Mypy), Pytest with coverage,
    frontend lint/typecheck/build/test, security audits (Bandit, pip-audit, npm audit, Trivy),
    and Docker build validation.
  - Release: automated container tagging and GHCR publishing on version tags.

### Phase 7: Validation and Demo (next)

- Fixture package tests: clean packages, packages with benign build differences,
  and packages with injected suspicious patterns.
- Measure false positives and false negatives on fixtures.
- Demo walkthrough and UI integration polish.
