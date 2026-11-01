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

### Phase 4: Static Security Scanner & Provenance / Risk Engine (done)

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
- Done (Part A — Provenance):
  - Check npm SLSA provenance attestations under Sigstore public trust root.
  - Inspect GitHub Actions build identity (Fulcio OID certificate extensions for source repository, commit, ref, workflow, and OIDC issuer).
  - Evaluate package integrity metadata against actual tarball SHA-512 / SHA-1 bytes.
  - Strict statuses: `VERIFIED`, `NOT_VERIFIED`, `UNAVAILABLE`, `INVALID`, `UNCERTAIN`.
  - Guardrails: Pydantic model validator prevents claiming verification based on metadata alone.
- Done (Part B — Risk Engine):
  - Deterministic 0–100 heuristic scoring derived from unexpected package differences, security findings, artifact uncertainty, source matching confidence, provenance results, and unexpected lifecycle scripts.
  - Returns complete contract: `level`, `score`, `contributing_evidence`, `confidence`, `recommendations`, and `limitations`.
  - Core safety rules: missing provenance alone awards 0 points and never implies maliciousness; clean findings with uncertain source or binaries does not imply safety.

### Phase 5: AI Investigator (done)

- Connects to Ollama with `qwen2.5-coder:7b` to explain findings with structured JSON output.
- Supplies real deterministic findings and source/package excerpts; model is barred from
  inventing evidence or altering deterministic risk results.
- Schema validation with Pydantic (`FindingExplanation`, `AIInvestigationResult`).
- Automated graceful offline fallback when Ollama is unavailable.

### Phase 6: Scan Orchestration & REST Endpoints (done)

- Full pipeline wiring: `Package input → npm fetcher → GitHub source resolver → safe extraction → inventory → comparison → artifact classification → security scanner → provenance checker → risk engine → AI investigator → integrity report`.
- Real scan statuses and progression tracking (no fake timers or synthetic progress).
- Complete REST API endpoints:
  - `POST /api/v1/scans`: Initiates and queues asynchronous scans.
  - `GET /api/v1/scans/{scan_id}`: Real-time scan state, stage, and progress percentage.
  - `GET /api/v1/scans/{scan_id}/report`: Full analysis report.
  - `GET /api/v1/scans/{scan_id}/files`: Complete file inventory and comparison classifications.
  - `GET /api/v1/scans/{scan_id}/files/{file_id}/diff`: File diff for a specific file by path or index.
  - `GET /api/v1/scans/{scan_id}/findings`: Security findings and AI investigator explanations.
- Validated with end-to-end live npm package scan (`left-pad@1.3.0`) and mock integration tests.
- Production-grade GitHub Actions CI/CD workflows (CI & Release).

### Phase 7: Validation and Demo (next)

- Fixture package tests: clean packages, packages with benign build differences,
  and packages with injected suspicious patterns.
- Measure false positives and false negatives on fixtures.
- Demo walkthrough and UI integration polish.
