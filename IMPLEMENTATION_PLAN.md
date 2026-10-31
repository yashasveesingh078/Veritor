# Implementation Plan

This is a plan, not a description of working software. Only Phase 0, the API
foundation, the npm part of Phase 1, safe extraction, GitHub source discovery,
the file comparison in Phase 3, static analysis and provenance checks in Phase 4
and risk scoring are done. None of the retrieval code is connected to the API yet.

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
and a validate-only `POST /api/v1/scans`. Scans are not stored or processed yet.

### Phase 1: Fetch artifacts

- Done for npm: `PackageAdapter` interface, exact-version metadata, and tarball
  download verified against registry hashes. Not yet connected to the API.
- To do: PyPI adapter.
- To do: compare registry metadata with the `package.json` inside the tarball,
  because publishers can make the two disagree.
- Done: safe extraction and file inventory for npm and GitHub archives. Not yet
  connected to the API.

### Phase 2: Locate source

- Done for GitHub: find the repository from package metadata, match the version
  to a commit using the recorded commit and tags, record the method and
  confidence, and download the archive for that exact commit.
- A version with no established match is `UNCERTAIN`. No default branch is ever
  used in its place.
- To do: support repositories outside GitHub.

### Phase 3: Compare

- Done: compare inventories by SHA-256, with per-file JSON evidence and text
  diffs. Each file is identical, added, removed, modified, binary-different or
  renamed. Renames need an exact, unambiguous content match.
- Done: classify differing files as `LIKELY_GENERATED` only with build evidence
  from the source repository and a link from that file to its source. Everything
  else is `UNCERTAIN`. No directory name is trusted on its own.
- Done: confirm the `package.json` at the matched commit has the same name and
  version, and report any disagreement as a warning.
- To do: rebuild from source, because `LIKELY_GENERATED` shows a file looks like
  build output, not that its content is what the build produced.

### Phase 4: Detect risk

- Done: AST-based scanning of added and modified JavaScript and TypeScript for
  dynamic execution, child processes, environment access, network calls,
  obfuscation and sensitive filesystem access, plus install scripts.
- Done: rule, path, line, severity, confidence, evidence and recommendation on
  every finding. Isolated API use stays low severity, and files that could not
  be scanned are reported as gaps.
- Done: npm provenance verified with Sigstore against the downloaded tarball.
- Done: deterministic risk score, with each point traced to a factor. A score
  is a triage signal, not a verdict.
- To do: use verified provenance to resolve an `UNCERTAIN` source match.
- To do: flag a release that lost provenance its earlier versions had.
- To do: scan shell and Python files, which are currently reported as gaps.

### Phase 5: Model interpretation

- `phi4-mini` sorts flagged differences by urgency.
- `qwen2.5-coder:7b` explains what the flagged code changes do.
- Validate model output against a schema. Keep the report usable if Ollama is
  unavailable.
- Test with prompt-injection samples embedded in package files.

### Phase 6: API and interface

- Connect `POST /api/v1/scans` to the analysis, and add endpoints to check
  progress and fetch the report.
- Add a frontend form, progress view, and findings view with diffs.

### Phase 7: Validation and demo

- Build fixtures: clean packages, packages with benign build differences, and
  locally built packages with injected changes.
- Measure false positives and false negatives on those fixtures.
- Prepare the demo and final documentation.

## Open decisions

- Product name: the repository uses Veritor, while `hackathon.md` uses TrueShip.
- Persistence: reports may be in memory or stored in SQLite.
- Rebuild scope: which build systems Phase 3 can reproduce in the time available.
