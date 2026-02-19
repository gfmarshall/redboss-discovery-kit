# Red Boss Discovery Kit - Quick Start Guide

**DISCLAIMER**: *This tool is provided "as is" without warranty of any kind, express or implied. It is designed exclusively for read-only metadata discovery and inventory. The authors and Red Boss assume no liability for any unintended consequences, data handling, or compliance issues arising from its use. Users are responsible for verifying that the tool's operation aligns with their internal security and operational policies.*

The **Red Boss Discovery Kit (DK Core)** is a read-only, metadata-only utility designed to safely discover and inventory JBoss EAP environments.

It performs on-host scanning to produce:
- **Instance Inventory**: Structured `summary.json` for each discovered JBoss instance.
- **Fingerprints**: `fingerprints.json` containing SHA-256 hashes of deployments and configurations (no files are copied).
- **SBOMs**: CycloneDX Software Bill of Materials for platform and application scopes.
- **Attestation**: A `dk-pack.json` verifying that no binaries or sensitive configurations were exported.

**Non-Negotiable Safety Boundaries:**
- **NO Binaries**: Never exports `.jar`, `.war`, `.ear`, `.zip`, or `.tar` files.
- **NO Raw Configs**: Never exports raw `.xml` configuration files.
- **NO Vulnerability Analysis**: Does not perform CVE lookups or assign risk ratings.
- **On-Host Only**: All computation happens where the files live; output is metadata only.

## 1. Prerequisites
- **OS:** RHEL 8.x (or compatible Linux)
- **Python:** 3.9+
- **SBOM Tool:** `syft` (See [Section 2: Syft Requirement](#2-syft-requirement) below)
- **Permissions:** Read access to JBoss installation and application deployment directories.

## 2. Syft Requirement
The Discovery Kit relies on **Anchore Syft** to generate Software Bill of Materials (SBOM) in CycloneDX format. This is a critical component for identifying nested dependencies within JBoss platforms and applications.

### Installation Options
You can provide `syft` in one of two ways:

1.  **System PATH:** Install `syft` globally so it is available as a command.
    ```bash
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
    ```
2.  **Local Bin:** Place the `syft` binary directly into the `bin/` directory of the Discovery Kit.
    ```bash
    mkdir -p bin/
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ./bin
    ```

The `dk` script will prioritize a binary in `bin/syft` before searching your system `PATH`.

## 3. Installation
The Discovery Kit is a standalone Python utility.
```bash
git clone <repo-url>
cd redboss-discovery-kit
pip install -r requirements.txt
```

## 4. Configuration
DK Core utilizes a **declarative, manifest-driven discovery architecture**. The operational scope—including JBoss binary locations, instance search roots, and identification markers—is defined within a manifest file (YAML or JSON). 

This approach ensures that discovery is deterministic, repeatable, and restricted to authorized paths. 

*   **Default Manifest**: The tool automatically loads `dk-manifest.yml` from the current directory if no manifest is specified.
*   **Custom Manifest**: Use the `--manifest <path>` flag to point to a specific configuration.
*   **Discovery Logic**: The tool resolves JBoss Home (using globs if necessary) and identifies standalone instances by matching directory markers (e.g., `configuration/`, `deployments/`) defined in the manifest.

Refer to `dk-manifest-reference.yml` for a fully documented schema of all configuration blocks.

## 5. Execution

### Validate Manifest
```bash
./dk validate-manifest --manifest my-manifest.yml
```

### Pre-flight (Dry-run)
Verify instance discovery without writing any output:
```bash
./dk dry-run
```
(By default, this uses `dk-manifest.yml`)

### Run Discovery
```bash
./dk run
```
By default, this uses `dk-manifest.yml` and writes output to `./generated-evidence/`.

### Archive Evidence
To package the evidence into a compressed `.tar.gz` archive:
```bash
./dk run --archive
```
This will create a timestamped tarball (e.g., `generated-evidence/260218-1830.tar.gz`) alongside the raw output directory.

### Convert Manifest Format
Convert between YAML and JSON:
```bash
./dk manifest convert --in dk-manifest.yml                  # → dk-manifest.json
./dk manifest convert --in dk-manifest.json --out custom.yml # explicit output
```

## 6. Output Structure
Each run produces a timestamped directory in `./generated-evidence/` containing:
- `dk-pack.json`: Global run metadata, safety attestation, and `instance_errors` array.
- `manifest.input.yml`: Verbatim copy of your input.
- `manifest.used.json`: Normalized version of the manifest used.
- `[instance-name]/`:
    - `summary.json`: Instance metadata (version, path, config).
    - `fingerprints.json`: SHA-256 hashes of all deployments.
    - `sbom.platform.cdx.json`: Platform-scope SBOM.
    - `sbom.apps.cdx.json`: Application-scope SBOM.
    - `sbom.all.cdx.json`: Combined instance SBOM.

All output artifacts are validated against JSON Schemas defined in `schemas.py`.

## 7. Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DK_LOG_FORMAT` | `json` | Set to `text` for human-readable logs instead of structured JSON. |
| `DK_SUBPROCESS_TIMEOUT` | `300` | Syft subprocess timeout in seconds. |
| `DK_SUBPROCESS_RETRIES` | `2` | Number of retry attempts for failed Syft calls. |
| `DK_MAX_WORKERS` | `4` | Maximum parallel threads for instance processing. |

## 8. Development

```bash
pip install -e ".[dev]"
pre-commit install

# Run tests
python -m pytest tests/ -v --cov=. --cov-report=term-missing

# Lint
ruff check .
ruff format --check .
```

See [TUTORIAL.md](TUTORIAL.md) for the full step-by-step tutorial. See [CONTRIBUTING.md](CONTRIBUTING.md) for developer guidelines. See [CHANGELOG.md](CHANGELOG.md) for release history.

---
*Red Boss - Runtime Governance & Mitigation*
