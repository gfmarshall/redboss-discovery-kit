# Red Boss Discovery Kit — Tutorial

A complete step-by-step guide to installing, configuring, running, and extending the Red Boss Discovery Kit (DK Core).

---

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Installation](#3-installation)
4. [Understanding the Manifest](#4-understanding-the-manifest)
5. [Your First Discovery Run](#5-your-first-discovery-run)
6. [CLI Command Reference](#6-cli-command-reference)
7. [Understanding the Output](#7-understanding-the-output)
8. [Working with Manifests](#8-working-with-manifests)
9. [Safety Model](#9-safety-model)
10. [Structured Logging & Observability](#10-structured-logging--observability)
11. [Performance Tuning](#11-performance-tuning)
12. [Troubleshooting](#12-troubleshooting)
13. [Integrating with CI/CD](#13-integrating-with-cicd)
14. [Schema Contracts & Downstream Consumers](#14-schema-contracts--downstream-consumers)
15. [Contributing & Development](#15-contributing--development)

---

## 1. Overview

The **Red Boss Discovery Kit (DK Core)** is a read-only, metadata-only utility that discovers and inventories JBoss EAP environments. It runs on the host where JBoss is installed and produces structured evidence — never copying binaries, raw configuration files, or performing vulnerability analysis.

### What it produces

| Artifact | Description |
|---|---|
| `summary.json` | Per-instance metadata: name, base path, selected config, mode, timestamp. |
| `fingerprints.json` | SHA-256 hashes, sizes, and modification times for deployments and configs. |
| `sbom.platform.cdx.json` | CycloneDX SBOM of the JBoss platform (excludes deployments). |
| `sbom.apps.cdx.json` | CycloneDX SBOM of application deployments only. |
| `sbom.all.cdx.json` | Combined CycloneDX SBOM of the entire instance. |
| `dk-pack.json` | Global run metadata, manifest hash, safety attestation, and error summary. |

### What it will never do

- Export `.jar`, `.war`, `.ear`, `.zip`, `.tar`, `.tgz`, or `.gz` files
- Export raw XML configuration files
- Perform CVE lookups or assign risk ratings
- Modify any file on the host system

---

## 2. Prerequisites

### Required

| Requirement | Version | Notes |
|---|---|---|
| **Operating System** | RHEL 8.x / compatible Linux | Tested on RHEL, CentOS, Ubuntu, Amazon Linux |
| **Python** | 3.9+ | Check with `python3 --version` |
| **Anchore Syft** | Latest | Required for SBOM generation |
| **File permissions** | Read access | To JBoss installation and deployment directories |

### Verifying Python

```bash
python3 --version
# Python 3.10.14 (or any 3.9+)
```

If Python 3.9+ is not available, consult your system administrator or use `pyenv` to install a compatible version.

### Installing Syft

Syft is the SBOM engine that DK Core uses under the hood. You have two options:

**Option A — System-wide install (recommended for servers):**

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

**Option B — Local install (no root required):**

```bash
mkdir -p bin/
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ./bin
```

DK Core checks for `bin/syft` in its own directory first, then falls back to the system `PATH`.

**Verify Syft:**

```bash
syft version
# or
./bin/syft version
```

---

## 3. Installation

### Step 1 — Clone the repository

```bash
git clone https://github.com/<org>/redboss-discovery-kit.git
cd redboss-discovery-kit
```

Or, if using a release tarball:

```bash
tar xzf redboss-discovery-kit-v2.0.0.tar.gz
cd redboss-discovery-kit-v2.0.0
```

### Step 2 — Install Python dependencies

```bash
pip install -r requirements.txt
```

This installs:
- **PyYAML** — for reading YAML manifests
- **jsonschema** — for validating manifests and output against JSON Schemas

### Step 3 — Verify the installation

```bash
python3 dk --help
```

Expected output:

```
usage: dk [-h] {run,dry-run,validate-manifest,manifest} ...

Red Boss Discovery Kit (DK Core)

positional arguments:
  {run,dry-run,validate-manifest,manifest}
                        Commands
    run                 Run discovery and metadata collection
    dry-run             Show discovery results without writing evidence
    validate-manifest   Validate manifest schema
    manifest            Manifest operations

optional arguments:
  -h, --help            show this help message and exit
```

### Step 4 — Verify Syft integration

```bash
python3 dk dry-run --manifest dk-manifest.yml
```

If this runs without error (even if no instances are found on your machine), your installation is correct.

---

## 4. Understanding the Manifest

The manifest is the single source of truth for what DK Core discovers. It is a YAML (or JSON) file that declares:

- **Where JBoss is installed** (`jboss.home`)
- **Where to search for instances** (`instances.discovery.roots`)
- **How to identify an instance** (globs, subdirectory candidates, marker directories)
- **Which config file to select** (`instances.config`)
- **What to scan and exclude** (`scan`)
- **Safety policy** (`safety.never_export_file_types`)

### Minimal manifest

The smallest valid manifest:

```yaml
manifest_version: 1

jboss:
  home: "/opt/jboss-eap-7.4"

instances:
  discovery:
    roots:
      - "/opt/jboss-eap-7.4"
```

### Full manifest walkthrough

```yaml
# ─── Required ───────────────────────────────────────────────
manifest_version: 1                    # Schema version (must be 1)

jboss:
  home: "/jboss/jboss-eap-7.3/**"     # Path or glob to JBoss home
  mode: "standalone"                   # "standalone" or "domain"

instances:
  discovery:
    roots:                             # Directories to search
      - "/jboss/instances/jboss-eap-7.3/dev"

    instance_globs:                    # Which subdirs count as instances
      - "*-instance"                   # e.g. "myapp-instance"

    base_subdir_candidates:            # Where to look for the base dir
      - "."                            # Layout A: <instance>/configuration/
      - "standalone"                   # Layout B: <instance>/standalone/configuration/

    base_markers:                      # Dirs that must exist to confirm
      - "configuration"
      - "deployments"

  config:
    candidates:                        # Config files to try (in order)
      - "standalone.xml"
      - "standalone-full.xml"
    # selected: "standalone-custom.xml"  # Uncomment to force a specific file

# ─── Optional ───────────────────────────────────────────────
sbom:
  formats: ["cyclonedx-json"]
  scopes: ["platform", "apps", "all"]

scan:
  platform_exclude:                    # Globs excluded from platform SBOM
    - "**/deployments/**"
    - "**/log/**"
    - "**/tmp/**"
    - "**/data/**"
  apps_include:                        # Globs included in apps SBOM
    - "deployments/**"

safety:
  never_export_file_types:             # Extensions that will NEVER be exported
    - ".jar"
    - ".war"
    - ".ear"
    - ".zip"
    - ".tar"
    - ".tgz"
    - ".gz"
```

### Discovery logic explained

DK Core uses a multi-step resolution process:

```
1. Resolve jboss.home
   └─ Expand globs → find dir with jboss-modules.jar

2. For each root in instances.discovery.roots:
   └─ For each glob in instance_globs:
      └─ For each matching directory:
         └─ For each candidate in base_subdir_candidates:
            └─ If ALL base_markers exist → instance found
               └─ Select config from config.candidates
```

**Example file system:**

```
/jboss/instances/jboss-eap-7.3/dev/
├── myapp-instance/            ← matched by "*-instance" glob
│   ├── configuration/         ← base_marker ✓
│   │   └── standalone.xml     ← selected config
│   └── deployments/           ← base_marker ✓
│       └── myapp.war
└── batch-instance/
    ├── configuration/
    │   └── standalone-full.xml
    └── deployments/
        └── batch-job.war
```

With the default manifest, DK Core discovers both `myapp-instance` and `batch-instance`.

---

## 5. Your First Discovery Run

This section walks through a complete end-to-end run.

### Step 1 — Create your manifest

Copy the default manifest and edit it for your environment:

```bash
cp dk-manifest.yml my-manifest.yml
```

Edit `my-manifest.yml` to match your JBoss layout:

```yaml
manifest_version: 1

jboss:
  home: "/opt/jboss-eap-7.4"

instances:
  discovery:
    roots:
      - "/opt/jboss-eap-7.4/instances"
    instance_globs:
      - "*"
    base_subdir_candidates:
      - "."
      - "standalone"
    base_markers:
      - "configuration"
      - "deployments"

  config:
    candidates:
      - "standalone.xml"
```

### Step 2 — Validate the manifest

```bash
./dk validate-manifest --manifest my-manifest.yml
```

**Success:**

```json
{"ts":"2026-02-20T10:00:01.123456+00:00","level":"INFO","msg":"Validating manifest: my-manifest.yml","logger":"dk","run_id":"a1b2c3d4e5f6"}
{"ts":"2026-02-20T10:00:01.125000+00:00","level":"INFO","msg":"✅ Manifest schema validation passed.","logger":"dk","run_id":"a1b2c3d4e5f6"}
```

**Failure (example — missing `jboss.home`):**

```json
{"ts":"...","level":"ERROR","msg":"  ✘ 'home' is a required property","logger":"dk","run_id":"..."}
{"ts":"...","level":"ERROR","msg":"Manifest validation failed with 1 error(s).","logger":"dk","run_id":"..."}
```

> **Tip:** Set `DK_LOG_FORMAT=text` for human-readable output during development:
> ```bash
> DK_LOG_FORMAT=text ./dk validate-manifest --manifest my-manifest.yml
> ```

### Step 3 — Dry-run (pre-flight check)

Verify what DK Core would discover, without writing any files:

```bash
./dk dry-run --manifest my-manifest.yml
```

Review the output to confirm the correct instances were found and the right configuration files were selected.

### Step 4 — Run discovery

```bash
./dk run --manifest my-manifest.yml
```

This creates a timestamped directory under `./generated-evidence/`:

```
generated-evidence/
└── 260220-1000/                     ← YYMMDD-HHMM (UTC)
    ├── dk-pack.json
    ├── manifest.input.yml
    ├── manifest.used.json
    ├── myapp-instance/
    │   ├── summary.json
    │   ├── fingerprints.json
    │   ├── sbom.platform.cdx.json
    │   ├── sbom.apps.cdx.json
    │   └── sbom.all.cdx.json
    └── batch-instance/
        ├── summary.json
        ├── fingerprints.json
        ├── sbom.platform.cdx.json
        ├── sbom.apps.cdx.json
        └── sbom.all.cdx.json
```

### Step 5 — Archive the evidence (optional)

```bash
./dk run --manifest my-manifest.yml --archive
```

This creates the same output **plus** a `.tar.gz` archive alongside the run directory:

```
generated-evidence/
├── 260220-1000/
│   └── ...
└── 260220-1000.tar.gz              ← portable evidence package
```

### Step 6 — Inspect the results

```bash
# Global attestation
cat generated-evidence/260220-1000/dk-pack.json | python3 -m json.tool

# Instance summary
cat generated-evidence/260220-1000/myapp-instance/summary.json | python3 -m json.tool

# Deployment fingerprints
cat generated-evidence/260220-1000/myapp-instance/fingerprints.json | python3 -m json.tool
```

---

## 6. CLI Command Reference

### `dk run`

Run full discovery and evidence generation.

```
./dk run [--manifest PATH] [--out DIR] [--archive]
```

| Flag | Default | Description |
|---|---|---|
| `--manifest` | `dk-manifest.yml` or `dk-manifest.json` | Path to manifest file |
| `--out` | `./generated-evidence/` | Output directory |
| `--archive` | `false` | Also create a `.tar.gz` archive of the evidence |

### `dk dry-run`

Show what would be discovered, without writing anything.

```
./dk dry-run [--manifest PATH]
```

### `dk validate-manifest`

Validate a manifest against the JSON Schema.

```
./dk validate-manifest [--manifest PATH]
```

Returns exit code `0` on success, `1` on validation failure.

### `dk manifest convert`

Convert a manifest between YAML and JSON formats.

```
./dk manifest convert --in PATH [--out PATH]
```

| Flag | Required | Description |
|---|---|---|
| `--in` | Yes | Input manifest file |
| `--out` | No | Output file. If omitted, swaps the extension (`.yml` → `.json` or vice versa). |

**Examples:**

```bash
# YAML → JSON (auto-named)
./dk manifest convert --in dk-manifest.yml
# Creates: dk-manifest.json

# JSON → YAML with explicit output
./dk manifest convert --in dk-manifest.json --out custom.yml
```

### Default manifest resolution

When `--manifest` is not provided, DK Core searches the current directory in order:

1. `dk-manifest.yml`
2. `dk-manifest.json`

If neither exists, it exits with an error.

---

## 7. Understanding the Output

### `dk-pack.json` — Run attestation

The top-level metadata file for the entire run.

```json
{
  "tool_version": "2.0.0-dk-core",
  "syft_version": "Application:   syft",
  "manifest_hash": "ad4fd61de11ca4e3add95b288ba69d6c55080079a81e...",
  "instance_count": 2,
  "timestamp": "2026-02-20T10:00:45.735888+00:00",
  "attestation": {
    "no_binaries_exported": true,
    "config_files_hashed_only": true
  },
  "instance_errors": []
}
```

| Field | Description |
|---|---|
| `tool_version` | Version of DK Core that produced this evidence. |
| `syft_version` | Version of Syft used for SBOM generation. |
| `manifest_hash` | SHA-256 of the input manifest (for tamper detection). |
| `instance_count` | Number of instances discovered. |
| `timestamp` | UTC ISO-8601 timestamp of the run. |
| `attestation` | Safety guarantees (always `true` by design). |
| `instance_errors` | Array of `{"instance": "...", "error": "..."}` for any failures. Empty on success. |

### `summary.json` — Instance metadata

One per discovered instance.

```json
{
  "instance_name": "standalone",
  "instance_base": "/opt/jboss-eap-7.4/standalone",
  "selected_config": "standalone.xml",
  "jboss_home": "/opt/jboss-eap-7.4",
  "mode": "standalone",
  "timestamp": "2026-02-20T10:00:37.924717+00:00"
}
```

### `fingerprints.json` — File hashes

An array of SHA-256 fingerprints for selected configs and deployments.

```json
[
  {
    "path": "/opt/jboss-eap-7.4/standalone/configuration/standalone.xml",
    "size_bytes": 1604,
    "mtime": "2026-02-19T18:06:23.724932+00:00",
    "sha256": "ff133c3f70bd65092c6627e8080ab17f22cffb48dcaafd0b728bd914f4293964"
  },
  {
    "path": "/opt/jboss-eap-7.4/standalone/deployments/sample-app.war",
    "size_bytes": 685,
    "mtime": "2026-02-19T18:06:23.725932+00:00",
    "sha256": "d02e80e388dd04b9ffa835d5b939c05e532a195e64dc8689123e88bf844c47e8"
  }
]
```

> **Note:** Only metadata (path, size, mtime, hash) is recorded. The files themselves are never copied.

### SBOM files

Three CycloneDX JSON SBOMs per instance:

| File | Scope | Description |
|---|---|---|
| `sbom.platform.cdx.json` | Platform | JBoss home + instance base, excluding deployments/logs/tmp/data |
| `sbom.apps.cdx.json` | Applications | Deployment directory only |
| `sbom.all.cdx.json` | Combined | Entire instance base |

These are standard CycloneDX 1.x JSON documents consumable by any SBOM-aware tool (Dependency-Track, Grype, etc.).

---

## 8. Working with Manifests

### Glob patterns in `jboss.home`

If your JBoss installation has nested extraction directories (common with automated provisioning), use a glob:

```yaml
jboss:
  home: "/opt/jboss/jboss-eap-*/**"
```

DK Core expands the glob recursively and selects the first directory containing `jboss-modules.jar`.

### Multiple discovery roots

Scan across multiple environments or mount points:

```yaml
instances:
  discovery:
    roots:
      - "/opt/jboss/instances/dev"
      - "/opt/jboss/instances/staging"
      - "/mnt/shared/jboss/instances"
```

### Handling different directory layouts

JBoss instances can follow different layouts. Use `base_subdir_candidates` to support both:

```yaml
instances:
  discovery:
    base_subdir_candidates:
      - "."            # Layout A: <instance>/configuration/
      - "standalone"   # Layout B: <instance>/standalone/configuration/
```

DK Core tries each candidate in order and selects the first where all `base_markers` exist.

### Forcing a specific configuration file

By default, DK Core selects the first matching file from `config.candidates`. To override:

```yaml
instances:
  config:
    selected: "standalone-custom.xml"
    candidates:
      - "standalone.xml"
      - "standalone-full.xml"
```

If `selected` is set, it takes priority. If the selected file doesn't exist, candidates are tried as fallback.

### Converting between YAML and JSON

Some teams prefer JSON manifests for machine generation. Convert freely:

```bash
# YAML → JSON
./dk manifest convert --in dk-manifest.yml

# JSON → YAML
./dk manifest convert --in dk-manifest.json

# Explicit output path
./dk manifest convert --in dk-manifest.yml --out /tmp/manifest.json
```

### Manifest version compatibility

The manifest includes a `manifest_version` field. DK Core validates this on load:

```yaml
manifest_version: 1   # Currently the only supported version
```

If you load a manifest with an unsupported version (e.g., from a future release), DK Core will reject it with a clear error message telling you which versions it supports.

---

## 9. Safety Model

DK Core enforces a strict safety policy at multiple levels.

### The `SafetyGuard`

Every file path that DK Core considers writing passes through the `SafetyGuard` class, which checks the extension against the `never_export_file_types` list in the manifest.

**Default blocked extensions:** `.jar`, `.war`, `.ear`, `.zip`, `.tar`, `.tgz`, `.gz`

If a write is attempted for a blocked extension, DK Core raises a `DKError` and halts that operation.

### Customizing the safety policy

You can restrict additional extensions:

```yaml
safety:
  never_export_file_types:
    - ".jar"
    - ".war"
    - ".ear"
    - ".zip"
    - ".tar"
    - ".tgz"
    - ".gz"
    - ".class"    # Also block compiled Java classes
    - ".so"       # Block native libraries
```

> **Warning:** Removing extensions from this list weakens the safety guarantee. The `dk-pack.json` attestation reflects the policy that was active during the run, so auditors can verify compliance.

### Attestation in `dk-pack.json`

Every run records a safety attestation:

```json
"attestation": {
  "no_binaries_exported": true,
  "config_files_hashed_only": true
}
```

These fields are always `true` by design — DK Core's architecture makes it structurally impossible to export binaries or raw configs. The attestation exists so downstream consumers can programmatically verify the evidence was produced under the expected safety guarantees.

---

## 10. Structured Logging & Observability

### JSON log output

By default, DK Core emits structured JSON logs to `stderr`:

```json
{"ts": "2026-02-20T10:00:01.123456+00:00", "level": "INFO", "msg": "Running DK Core with manifest: my-manifest.yml", "logger": "dk", "run_id": "a1b2c3d4e5f6"}
```

Every log entry includes:

| Field | Description |
|---|---|
| `ts` | UTC ISO-8601 timestamp |
| `level` | Log level: `INFO`, `WARNING`, `ERROR` |
| `msg` | Human-readable message |
| `logger` | Logger name (`dk`) |
| `run_id` | 12-character correlation ID (unique per invocation) |

### Human-readable mode

For interactive use, switch to plain-text output:

```bash
DK_LOG_FORMAT=text ./dk run
```

This produces:

```
INFO: Running DK Core with manifest: dk-manifest.yml
INFO: Processing 2 instances...
INFO:   --> Instance: myapp-instance
INFO: ✅ Run complete. Output in: generated-evidence/260220-1000
```

### Correlation IDs

The `run_id` is generated once per invocation and attached to every log entry. Use it to:

- **Filter logs** in aggregation systems (ELK, Splunk, CloudWatch)
- **Correlate** a specific `dk-pack.json` with its log trail
- **Debug** issues in multi-run environments

Example — grep for a specific run:

```bash
./dk run 2>logs.jsonl
cat logs.jsonl | python3 -c "
import sys, json
for line in sys.stdin:
    entry = json.loads(line)
    if entry.get('run_id') == 'a1b2c3d4e5f6':
        print(json.dumps(entry, indent=2))
"
```

---

## 11. Performance Tuning

### Environment variables

DK Core provides environment variables for tuning resilience and performance:

| Variable | Default | Description |
|---|---|---|
| `DK_LOG_FORMAT` | `json` | `json` for structured, `text` for plain output |
| `DK_SUBPROCESS_TIMEOUT` | `300` | Timeout (seconds) for each Syft subprocess call |
| `DK_SUBPROCESS_RETRIES` | `2` | Number of retry attempts if Syft fails or times out |
| `DK_MAX_WORKERS` | `4` | Maximum parallel threads for instance processing |

### Scaling for large environments

**Many instances (50+):**

```bash
DK_MAX_WORKERS=8 ./dk run --manifest prod-manifest.yml
```

Increase the thread pool to process more instances in parallel. Be mindful of disk I/O on the host.

**Slow Syft scans (large deployments):**

```bash
DK_SUBPROCESS_TIMEOUT=600 DK_SUBPROCESS_RETRIES=3 ./dk run
```

Increase the timeout and retries for environments with very large `.war` files or deep dependency trees.

**Minimal resources (embedded/constrained hosts):**

```bash
DK_MAX_WORKERS=1 DK_SUBPROCESS_TIMEOUT=120 ./dk run
```

### Retry behaviour

When Syft fails or times out, DK Core retries with exponential backoff:

```
Attempt 1 → fail → wait 2s
Attempt 2 → fail → wait 4s  (capped at 10s)
Attempt 3 → fail → logged as error, SBOM skipped
```

The run continues even if individual SBOMs fail. Failures are recorded in `dk-pack.json`'s `instance_errors` array, allowing downstream consumers to detect partial runs.

---

## 12. Troubleshooting

### "No manifest specified and dk-manifest.yml/json not found"

DK Core looks for `dk-manifest.yml` then `dk-manifest.json` in the current working directory. Either:

```bash
# Provide explicitly
./dk run --manifest /path/to/my-manifest.yml

# Or ensure you're in the right directory
cd /path/to/redboss-discovery-kit
./dk run
```

### "Unsupported manifest_version X"

Your manifest was created for a newer version of DK Core. Check the `manifest_version` field and either:
- Upgrade DK Core to a version that supports it
- Downgrade the manifest to version `1`

### "Manifest validation failed with N error(s)"

Run `validate-manifest` with text logging for readable errors:

```bash
DK_LOG_FORMAT=text ./dk validate-manifest --manifest my-manifest.yml
```

Common causes:
- Missing required key (e.g., `jboss.home`, `instances.discovery.roots`)
- Empty `jboss.home` string
- Safety extensions missing the leading dot (`war` instead of `.war`)

### "No instances discovered"

The discovery engine found no directories matching your criteria. Debug with:

```bash
DK_LOG_FORMAT=text ./dk dry-run --manifest my-manifest.yml
```

Check:
- Do the `roots` directories exist on this host?
- Do the `instance_globs` match the directory names?
- Do the `base_markers` directories (`configuration`, `deployments`) exist in the instances?

### Syft timeout / failure

If Syft consistently fails:

```bash
# Test Syft directly
syft /path/to/your/instance -o cyclonedx-json

# Increase DK timeout
DK_SUBPROCESS_TIMEOUT=600 DK_SUBPROCESS_RETRIES=3 ./dk run
```

Check `dk-pack.json` → `instance_errors` to see which instances failed and why.

### Permission denied errors

DK Core requires read access to all scanned directories. Verify:

```bash
# Check JBoss home
ls -la /opt/jboss-eap-7.4/

# Check instance roots
ls -la /opt/jboss/instances/

# Check specific instance
ls -la /opt/jboss/instances/myapp-instance/configuration/
```

---

## 13. Integrating with CI/CD

### Running in a pipeline

DK Core is designed for non-interactive execution. Example GitHub Actions step:

```yaml
- name: Run Discovery Kit
  run: |
    pip install -r requirements.txt
    DK_LOG_FORMAT=json python3 dk run \
      --manifest ${{ env.MANIFEST_PATH }} \
      --out evidence/ \
      --archive
  env:
    DK_MAX_WORKERS: 2
    DK_SUBPROCESS_TIMEOUT: 300

- name: Upload evidence
  uses: actions/upload-artifact@v4
  with:
    name: dk-evidence
    path: evidence/*.tar.gz
```

### Validating evidence programmatically

Use the exit code of `dk-pack.json`'s `instance_errors` to gate deployments:

```bash
# Check for zero errors
ERRORS=$(python3 -c "
import json, sys
pack = json.load(open('evidence/260220-1000/dk-pack.json'))
print(len(pack['instance_errors']))
")

if [ "$ERRORS" -ne 0 ]; then
  echo "DK run had $ERRORS instance error(s) — failing pipeline"
  exit 1
fi
```

### Comparing runs

Compare fingerprints between two runs to detect deployment changes:

```bash
diff <(python3 -m json.tool evidence/run1/myapp/fingerprints.json) \
     <(python3 -m json.tool evidence/run2/myapp/fingerprints.json)
```

---

## 14. Schema Contracts & Downstream Consumers

### Machine-readable schemas

All input and output contracts are defined as JSON Schemas in `schemas.py`:

| Schema | Validates |
|---|---|
| `MANIFEST_SCHEMA` | Input manifest (`dk-manifest.yml` / `.json`) |
| `SUMMARY_SCHEMA` | `summary.json` per instance |
| `FINGERPRINTS_SCHEMA` | `fingerprints.json` per instance |
| `DK_PACK_SCHEMA` | `dk-pack.json` global run metadata |

### Validating output externally

Downstream tools can validate DK Core output against the schemas:

```python
import json
import jsonschema
from schemas import DK_PACK_SCHEMA

with open("generated-evidence/260220-1000/dk-pack.json") as f:
    pack = json.load(f)

jsonschema.validate(pack, DK_PACK_SCHEMA)
print("dk-pack.json is valid")
```

### Building a consumer

Example: a Python script that reads all instance summaries from a run:

```python
import json
from pathlib import Path

run_dir = Path("generated-evidence/260220-1000")

# Read attestation
pack = json.loads((run_dir / "dk-pack.json").read_text())
print(f"Tool: {pack['tool_version']}, Instances: {pack['instance_count']}")

# Iterate instance evidence
for instance_dir in run_dir.iterdir():
    summary_path = instance_dir / "summary.json"
    if summary_path.exists():
        summary = json.loads(summary_path.read_text())
        fp_count = len(json.loads((instance_dir / "fingerprints.json").read_text()))
        print(f"  {summary['instance_name']}: {summary['selected_config']} ({fp_count} fingerprints)")
```

### Schema versioning

The `manifest_version` field gates compatibility:
- DK Core **2.x** supports `manifest_version: 1`
- Future versions may support higher versions while maintaining backward compatibility
- Manifests are never silently migrated — an unsupported version produces a clear error

---

## 15. Contributing & Development

### Setting up a development environment

```bash
git clone https://github.com/<org>/redboss-discovery-kit.git
cd redboss-discovery-kit
pip install -r requirements.txt
pip install -e ".[dev]"
pre-commit install
```

### Running the test suite

```bash
# Full suite with coverage
python3 -m pytest tests/ -v --cov=. --cov-report=term-missing

# Single test file
python3 -m pytest tests/test_sbom_orchestrator.py -v

# Single test
python3 -m pytest tests/test_dk.py::TestManifestValidation::test_valid_manifest_passes -v
```

The test suite includes:
- **38 tests** across 4 modules
- **76% coverage**
- Mocked Syft calls (no external binary required)
- Temporary directory fixtures for full isolation

### Linting

```bash
ruff check .           # Lint
ruff format --check .  # Format check
ruff format .          # Auto-format
```

### Project structure

```
redboss-discovery-kit/
├── dk                          # Main script (Python, extension-less)
├── schemas.py                  # JSON Schema definitions
├── dk-manifest.yml             # Default manifest
├── dk-manifest-reference.yml   # Annotated manifest reference
├── requirements.txt            # Runtime dependencies
├── pyproject.toml              # Project metadata + tool config
├── .pre-commit-config.yaml     # Pre-commit hooks
├── .github/
│   └── workflows/
│       ├── ci.yml              # PR pipeline: lint + test + security
│       └── release.yml         # Tag pipeline: test + package + publish
├── scripts/
│   └── package-release.sh      # Release tarball builder
├── tests/
│   ├── conftest.py             # Shared fixtures
│   ├── test_dk.py              # Core logic tests
│   ├── test_cmd_run.py         # CLI command tests
│   ├── test_sbom_orchestrator.py  # SBOM + retry tests
│   └── test_logging.py         # Structured logging tests
├── README.md                   # Quick-start guide
├── TUTORIAL.md                 # This file
├── CONTRIBUTING.md             # Developer guide
├── CHANGELOG.md                # Release history
├── ACKNOWLEDGEMENTS.md         # Third-party credits
└── LICENSE                     # Apache 2.0
```

### Creating a release

```bash
# Tag and push
git tag v2.1.0
git push origin v2.1.0
```

This triggers the release pipeline which:
1. Runs the full test suite
2. Packages a tarball via `scripts/package-release.sh`
3. Generates a SHA-256 checksum
4. Creates a GitHub Release with the tarball and checksum attached

---

*Red Boss - Runtime Governance & Mitigation*
