# HACKATHON.md

## Team Name
CommitCrew

## Team Members
1. Yashasvee Singh
2. Mansha Agarwal
3. Siddhi Varshney
4. Komal

## Selected Problem Statement
Problem 04: Published Package vs Source Code Integrity Analyzer

## Solution
Veritor compares packages published on npm and PyPI with their source
repositories, explains each difference with evidence, and flags
modifications that it cannot explain or that add risky behaviour.
## AI Models Used

### Phi-4 Mini (`phi4-mini`, via Ollama)
Reason: A small, fast open-weight model that suits a 16 GB laptop. It sorts
flagged differences by urgency, so the larger model reviews less code.

### Qwen2.5-Coder 7B (`qwen2.5-coder:7b`, via Ollama)
Reason: A code-focused open-weight model that runs locally. It explains what
flagged code changes do.

## How the Models Are Used
Code analysis collects the evidence first. The models then run one at a time
to sort and interpret it. They treat package contents as untrusted data and
cannot clear hard evidence, such as an untraceable new install script. All
models run locally.