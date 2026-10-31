# Veritor

Veritor compares packages published on npm and PyPI with their source
repositories, explains each difference with evidence, and flags modifications
that it cannot explain or that add risky behaviour.

**Status: early foundation.** The frontend shows a placeholder page. The backend
exposes `GET /health` and `POST /api/v1/scans`, which validates and acknowledges
a request but does not store it, retrieve the package or analyze anything. An
npm adapter can retrieve metadata and download verified tarballs, and a GitHub
resolver can match a version to a commit and download its source archive. Both
kinds of archive can be safely extracted, inventoried and compared file by file,
with build output classified from evidence in the source repository. Differing
JavaScript and TypeScript is scanned statically, npm provenance is verified with
Sigstore, and the results feed an explainable risk score. Package code is never
executed. None of this is connected to the API yet. See
[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for what is planned.

Built by team CommitCrew for Problem 04: Published Package vs Source Code
Integrity Analyzer. See [hackathon.md](hackathon.md).

## Layout

| Path | Contents |
| --- | --- |
| `frontend/` | Next.js app (TypeScript, App Router) |
| `backend/` | FastAPI app and Python configuration |
| `.github/workflows/ci.yml` | Lint, type check, test and build |

## Requirements

- Node.js 20.9 or newer
- Python 3.12 or newer

## Backend

```sh
cd backend
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp ../.env.example ../.env   # optional: the defaults work without it
uvicorn app.main:app --reload
```

The API runs at <http://127.0.0.1:8000>. To run the checks:

```sh
ruff check . && ruff format --check . && mypy && pytest
```

## Frontend

```sh
cd frontend
npm ci
npm run dev
```

The app runs at <http://localhost:3000>. To run the checks:

```sh
npm run lint && npm run typecheck && npm run build
```

## License

Licensed under the [Apache License 2.0](LICENSE).
