# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-02-20

### Added
- **JSON Schema validation** for manifests via `jsonschema` library (`schemas.py`).
- **Output JSON Schemas** for `summary.json`, `fingerprints.json`, and `dk-pack.json`.
- **Manifest version gate** — `load_manifest` rejects unsupported `manifest_version` values.
- **`SafetyGuard` class** — programmatic enforcement of `never_export_file_types` policy.
- **`DKError` custom exception** — all recoverable errors raise `DKError`; caught at CLI boundary.
- **`manifest convert` command** — bidirectional YAML ↔ JSON manifest conversion.
- **Structured JSON logging** with UTC timestamps and per-invocation correlation IDs (`RUN_ID`).
- **Subprocess resilience** — configurable timeouts (`DK_SUBPROCESS_TIMEOUT`), retries (`DK_SUBPROCESS_RETRIES`), and exponential backoff for Syft calls.
- **Explicit thread pool bounds** — `DK_MAX_WORKERS` env var (default 4).
- **Partial failure tracking** — `instance_errors` array in `dk-pack.json` records per-instance processing failures.
- **Comprehensive test suite** — 38 tests covering core logic, schema validation, SBOM orchestration, logging, and CLI commands.
- **`conftest.py`** with shared pytest fixtures (`jboss_env`, `valid_manifest`, `manifest_file`).
- **`pyproject.toml`** with pytest, coverage, and ruff configuration.
- **`.pre-commit-config.yaml`** — ruff lint/format + standard pre-commit hooks.
- **CI pipeline** (`.github/workflows/ci.yml`) — lint, test (Python 3.9–3.12), security scan on every PR.
- **Release pipeline** (`.github/workflows/release.yml`) — tag-triggered tarball + checksum + GitHub Release.
- **`scripts/package-release.sh`** — creates distributable tarball with SHA-256 checksum.
- **`CONTRIBUTING.md`** — developer guide with code standards, workflow, and release process.

### Changed
- All `sys.exit(1)` calls in library functions replaced with `raise DKError`.
- All timestamps now use `datetime.now(timezone.utc)` / `datetime.fromtimestamp(..., tz=timezone.utc)`.
- `cmd_validate` rewritten to use JSON Schema (with fallback to structural checks).
- `SbomOrchestrator.generate_sbom` now includes timeout and retry logic.
- `ThreadPoolExecutor` uses explicit `max_workers` bound.

### Fixed
- Duplicate `import subprocess` statement removed.
- Bare `except: pass` replaced with `except Exception:` + warning log.
- Deprecated `SourceFileLoader.load_module()` in tests replaced with `importlib.util.module_from_spec`.
- Test directory creation changed from CWD-relative `Path("test_env")` to `tempfile.mkdtemp`.

### Security
- `requirements.txt` now includes `jsonschema>=4.18`.
- CI pipeline includes `pip-audit` dependency scanning and ruff security rules (`S` selector).

## [1.0.0] - 2025-02-19

### Added
- Initial release of Red Boss Discovery Kit (DK Core).
- Manifest-driven JBoss instance discovery.
- SHA-256 fingerprinting of configurations and deployments.
- CycloneDX SBOM generation via Anchore Syft.
- Evidence packaging with `dk-pack.json` safety attestation.
