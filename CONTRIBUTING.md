# Contributing to Red Boss Discovery Kit

Thank you for your interest in contributing! This document outlines the process and standards for contributing to the project.

## Prerequisites

- Python 3.9+
- [Anchore Syft](https://github.com/anchore/syft) (for SBOM generation)
- Git

## Getting Started

```bash
git clone https://github.com/<org>/redboss-discovery-kit.git
cd redboss-discovery-kit
pip install -r requirements.txt
pip install -e ".[dev]"
pre-commit install
```

## Development Workflow

1. **Create a branch** from `main` for your work.
2. **Write tests first** — new features and bug fixes must include tests.
3. **Run linting and tests** before pushing:
   ```bash
   ruff check .
   ruff format --check .
   python -m pytest tests/ --cov=. --cov-fail-under=60
   ```
4. **Open a Pull Request** — CI will run lint, test (Python 3.9–3.12), and security scans automatically.

## Code Standards

- **No `sys.exit()` in library code** — raise `DKError` instead; catch at the CLI boundary only.
- **UTC timestamps everywhere** — use `datetime.now(timezone.utc)`.
- **JSON Schema validation** — manifest and output contracts are defined in `schemas.py`.
- **Safety policy enforcement** — never bypass `SafetyGuard`; the `never_export_file_types` list is law.
- **Structured logging** — all log output goes through the `logger` (JSON to stderr by default).

## Testing

- Tests live in `tests/` and use `pytest`.
- Shared fixtures are in `tests/conftest.py`.
- Mock external binaries (Syft) — do not require them in CI.
- Coverage must stay above 60%.

## Commit Messages

Use conventional-style messages:

```
feat: add manifest schema version gate
fix: correct UTC timestamp in fingerprints
test: add SbomOrchestrator retry coverage
docs: update README with new CLI options
```

## Release Process

Releases are automated via GitHub Actions when a version tag is pushed:

```bash
git tag v2.1.0
git push origin v2.1.0
```

This triggers the release workflow which runs tests, packages a tarball, generates a SHA-256 checksum, and creates a GitHub Release.

## Security

- Never log sensitive information (paths to credentials, tokens, PII).
- Dependencies are audited via `pip-audit` in CI.
- Report security issues privately — do not open public issues for vulnerabilities.
