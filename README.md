# Veritor

[![CI](https://github.com/yashasveesingh078/Veritor/actions/workflows/ci.yml/badge.svg)](https://github.com/yashasveesingh078/Veritor/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Veritor compares packages published on npm and PyPI with their source
repositories, explains each difference with evidence, and flags modifications
that it cannot explain or that add risky behaviour.

Built by team CommitCrew for Problem 04: Published Package vs Source Code
Integrity Analyzer. See [hackathon.md](hackathon.md) and [docs/CI-CD.md](docs/CI-CD.md).

---

## Layout

| Path | Contents |
| --- | --- |
| `frontend/` | Next.js 16 app (TypeScript, App Router, Tailwind CSS) |
| `backend/` | FastAPI app, safe tarball/git extraction, static security analyzer, Ollama AI investigator |
| `docs/CI-CD.md` | Detailed CI/CD architecture and security scanning documentation |
| `docker-compose.yml` | Full-stack orchestration (Frontend, Backend, Ollama) |
| `.github/workflows/ci.yml` | CI pipeline: linting, typing, pytest, npm test, security audits, Docker validation |
| `.github/workflows/release.yml` | CD pipeline: GHCR container publishing and GitHub Releases |

---

## Requirements

- Node.js 20.9+ (or Node.js 24)
- Python 3.12+
- Docker & Docker Compose (optional for containerized deployment)

---

## Backend

```sh
cd backend
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp ../.env.example ../.env   # optional: the defaults work without it
uvicorn app.main:app --reload
```

The API runs at <http://127.0.0.1:8000>.

### Backend Validation & Security Checks

```sh
# Linting & Formatting
ruff check . && ruff format --check .

# Type checking
mypy

# Tests & Coverage
pytest --cov=app --cov-report=term-missing

# Security SAST & Dependency Audits
bandit -r app -ll -ii
pip-audit .
```

---

## Frontend

```sh
cd frontend
npm ci
npm run dev
```

The app runs at <http://localhost:3000>.

### Frontend Validation & Security Checks

```sh
# Linting & Type check
npm run lint && npm run typecheck

# Unit tests
npm test

# Production build check
npm run build

# High-severity dependency audit
npm audit --audit-level=high
```

---

## Docker & Container Deployment

### Running with Docker Compose

To run the complete Veritor stack (backend, frontend, and Ollama AI engine):

```sh
docker compose up --build
```

- Frontend: <http://localhost:3000>
- Backend API & Swagger Docs: <http://localhost:8000/docs>
- Ollama API: <http://localhost:11434>

### Standalone Docker Builds

```sh
# Build backend
docker build -t veritor-backend:local ./backend

# Run backend
docker run -p 8000:8000 --env-file .env veritor-backend:local

# Build frontend
docker build -t veritor-frontend:local ./frontend

# Run frontend
docker run -p 3000:3000 -e NEXT_PUBLIC_API_URL=http://localhost:8000 veritor-frontend:local
```

---

## CI/CD Pipeline & Releases

Veritor uses automated GitHub Actions workflows:

1. **Continuous Integration (`ci.yml`)**:
   - Triggers on PRs to `main`, pushes to `main`, and manual dispatch.
   - Runs backend Ruff lint/format, Mypy typing, Pytest with code coverage artifact upload.
   - Runs frontend ESLint, TypeScript check, unit tests, and production build.
   - Runs multi-layer security scans: **Bandit** (Python SAST), **pip-audit** (Python CVEs), **npm audit** (Node CVEs), and **Trivy** (filesystem vulnerability and secret scanner).
   - Validates that Docker images build cleanly.

2. **Continuous Delivery & Releases (`release.yml`)**:
   - Triggers automatically when a semantic version tag is pushed (e.g., `git tag v1.0.0 && git push origin v1.0.0`) or via manual workflow dispatch.
   - Builds production multi-stage Docker images for backend and frontend.
   - Authenticates securely to GitHub Container Registry using `GITHUB_TOKEN`.
   - Tags and publishes images to `ghcr.io/<owner>/veritor-backend` and `ghcr.io/<owner>/veritor-frontend` with semver (`v1.0.0`), short commit SHA (`sha-abc1234`), and `latest`.
   - Automatically publishes a GitHub Release with auto-generated release notes.

For comprehensive details on security scanning thresholds, caching strategies, and release architecture, see [docs/CI-CD.md](docs/CI-CD.md).

---

## License

Licensed under the [Apache License 2.0](LICENSE).
