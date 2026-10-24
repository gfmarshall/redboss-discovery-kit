#!/usr/bin/env python3
"""ci/lib/wiring_emit.py

S42-07: wiring-corpus orchestrator (ADR-0019). Given a DK manifest it
emits the complete derived wiring corpus for one host into
<output-dir>/wiring/:

    wiring/module-graph.json               (per jboss.home)
    wiring/platform-fingerprints.json      (per jboss.home)
    wiring/<instance>/server-roots.json    (per discovered instance)
    wiring/<instance>/deployment-wiring.json
    wiring/wiring-manifest.json            (file->sha256, attestation)

Instance discovery mirrors the manifest contract: for each
instances.discovery.roots entry, directories matching instance_globs are
probed with base_subdir_candidates until one contains all base_markers;
the config is the first existing config.candidates entry under
<base>/configuration/ (or config.selected when set).

Determinism: artifact bodies carry no timestamps; generated_at lives in
the manifest. files[] is sorted by path.

Requires PyYAML (manifest parsing) — run under EVIDENCE_PYTHON. The
extractors themselves are stdlib-only.

Usage:
    wiring_emit.py --manifest PATH --output-dir DIR --host HOST \
        [--collection-mode live|offline-staged] \
        [--locator-key-env VAR | --insecure-unkeyed-locators]
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from wiring_classify import LocatorKey  # noqa: E402
import wiring_scan  # noqa: E402

GENERATOR_VERSION = "0.1.0"
LIB = Path(__file__).resolve().parent


def sha256_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def load_manifest(path: Path) -> dict:
    try:
        import yaml
    except ImportError:
        raise SystemExit(
            "PyYAML unavailable — run via EVIDENCE_PYTHON (evidence-venv)"
        )
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or "jboss" not in doc:
        raise SystemExit(f"manifest lacks jboss.* scope: {path}")
    return doc


def discover_instances(manifest: dict) -> list[dict]:
    discovery = manifest.get("instances", {}).get("discovery", {})
    globs = discovery.get("instance_globs") or ["*"]
    candidates = discovery.get("base_subdir_candidates") or ["."]
    markers = discovery.get("base_markers") or ["configuration", "deployments"]
    config = manifest.get("instances", {}).get("config", {})
    conf_candidates = config.get("candidates") or ["standalone.xml"]
    found = []
    for root in discovery.get("roots") or []:
        root_path = Path(root)
        if not root_path.is_dir():
            continue
        for entry in sorted(root_path.iterdir()):
            if not entry.is_dir():
                continue
            if not any(fnmatch.fnmatch(entry.name, g) for g in globs):
                continue
            base = None
            for cand in candidates:
                probe = entry / cand
                if all((probe / m).is_dir() for m in markers):
                    base = probe
                    break
            if base is None:
                continue
            conf = None
            if config.get("selected"):
                sel = base / "configuration" / config["selected"]
                conf = sel if sel.is_file() else None
            if conf is None:
                for name in conf_candidates:
                    probe = base / "configuration" / name
                    if probe.is_file():
                        conf = probe
                        break
            deployments = base / "deployments"
            found.append(
                {
                    "name": entry.name,
                    "base": base,
                    "config": conf,
                    "deployments": deployments if deployments.is_dir() else None,
                }
            )
    return found


def subprocess_runner(script: str, args: list[str]) -> bool:
    """Default runner: invoke each extractor as a subprocess (isolation)."""
    proc = subprocess.run(
        [sys.executable, str(LIB / script), *args],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(
            f"wiring_emit: {script} failed: {proc.stderr.strip()[:300]}",
            file=sys.stderr,
        )
        return False
    sys.stderr.write(proc.stderr)
    return True


def resolve_key(args) -> LocatorKey:
    import os
    env_val = os.environ.get(args.locator_key_env)
    if env_val:
        # Propagate to the canonical env var so extractor children resolve
        # the same engagement-scoped key.
        os.environ.setdefault("RB_WIRING_LOCATOR_KEY", env_val)
        return LocatorKey(env_val.encode("utf-8"))
    return LocatorKey.resolve(
        args.locator_key_file,
        args.insecure_unkeyed_locators
        or os.environ.get("RB_WIRING_CORPUS_UNKEYED") == "1",
    )


def emit_corpus(
    manifest_path: Path | None,
    output_dir: Path,
    host: str,
    collection_mode: str = "live",
    manifest: dict | None = None,
    locator_key_env: str = "RB_WIRING_LOCATOR_KEY",
    locator_key_file=None,
    insecure_unkeyed: bool = False,
    runner=subprocess_runner,
    generator_name: str = "ci/lib wiring corpus",
) -> int:
    """Emit the complete wiring corpus beneath <output_dir>/wiring/.

    ``runner`` is the extractor transport — subprocess_runner for the
    interim channel (process isolation); an in-process caller (DK Core
    vendored path) passes a runner invoking each module's main(argv)
    directly, so the same code works inside a frozen binary.

    ``manifest`` may be supplied as an already-parsed dict (DK Core's
    in-process path) — then ``manifest_path`` is unused and PyYAML is
    never needed.

    Returns 0 on full success, 1 on any extractor failure or a
    secrets-scan hit (artifacts are then deleted; the manifest still
    attests the failure).
    """
    class _Args:
        pass
    args = _Args()
    args.locator_key_env = locator_key_env
    args.locator_key_file = locator_key_file
    args.insecure_unkeyed_locators = insecure_unkeyed

    if manifest is None:
        manifest = load_manifest(Path(manifest_path).resolve())
    jboss_home = Path(manifest["jboss"]["home"]).resolve()
    if not jboss_home.is_dir():
        raise SystemExit(f"jboss.home not found: {jboss_home}")

    import os

    key = resolve_key(args)
    if key.keying == "unkeyed":
        print(
            "wiring_emit: unkeyed locators — attestation records it",
            file=sys.stderr,
        )

    wiring = Path(output_dir).resolve() / "wiring"
    wiring.mkdir(parents=True, exist_ok=True)

    common = [
        "--host", host,
        "--jboss-home", str(jboss_home),
        "--collection-mode", collection_mode,
    ]
    ok = True
    subjects = [{"jboss_home": str(jboss_home), "instances": []}]

    for script, out in (
        ("module_graph.py", wiring / "module-graph.json"),
        ("platform_fingerprints.py", wiring / "platform-fingerprints.json"),
    ):
        ok = runner(script, [*common, "--out", str(out)]) and ok

    for inst in discover_instances(manifest):
        subjects[0]["instances"].append(inst["name"])
        inst_dir = wiring / inst["name"]
        inst_dir.mkdir(parents=True, exist_ok=True)
        if inst["config"]:
            ok = runner(
                "server_roots.py",
                [
                    *common,
                    "--instance", inst["name"],
                    "--config", str(inst["config"]),
                    *(["--locator-key-file", str(locator_key_file)]
                      if locator_key_file else []),
                    *(["--insecure-unkeyed-locators"]
                      if key.keying == "unkeyed" else []),
                    "--out", str(inst_dir / "server-roots.json"),
                ],
            ) and ok
        else:
            print(
                f"wiring_emit: no config resolved for {inst['name']}",
                file=sys.stderr,
            )
            ok = False
        if inst["deployments"]:
            ok = runner(
                "deploy_wiring.py",
                [
                    *common,
                    "--instance", inst["name"],
                    "--deployments-dir", str(inst["deployments"]),
                    "--out", str(inst_dir / "deployment-wiring.json"),
                ],
            ) and ok

    files = []
    artifact_paths = []
    for f in sorted(wiring.rglob("*.json")):
        if f.name == "wiring-manifest.json":
            continue
        rel = f.relative_to(Path(output_dir).resolve()).as_posix()
        subject = (
            f.relative_to(wiring).parts[0]
            if len(f.relative_to(wiring).parts) > 1
            else "platform"
        )
        files.append({"path": rel, "sha256": sha256_file(f), "subject": subject})
        artifact_paths.append(str(f))

    # S42-08 pre-publish secrets-scan gate (ADR-0019). On a hit the
    # artifacts are deleted — they may carry the leaked value and must
    # never leave the host — while the manifest survives to attest the
    # failure (it carries only paths and hashes).
    scan_hits = wiring_scan.scan(artifact_paths) if artifact_paths else {}
    secrets_scan = "failed" if scan_hits else "passed"
    if scan_hits:
        for path, hits in scan_hits.items():
            shown = ", ".join(f"L{ln}:{name}" for ln, name in hits[:3])
            print(f"wiring_emit: secrets-scan HIT {path}: {shown}", file=sys.stderr)
        for f in artifact_paths:
            Path(f).unlink(missing_ok=True)
        files = []
        ok = False
        print(
            "wiring_emit: secrets-scan failed — corpus artifacts removed, "
            "manifest attests failure",
            file=sys.stderr,
        )

    manifest_doc = {
        "schema_version": "1",
        "artifact": "wiring-manifest",
        "generator": {"name": generator_name, "version": GENERATOR_VERSION},
        "host": host,
        "collection_mode": collection_mode,
        "generated_at": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "files": files,
        "attestation": {
            "raw_file_bodies_exported": False,
            "sensitivity_model": {
                "classes": ["structural", "locator", "secret-shaped"],
                "locator_key_derivation": "hmac-sha256(engagement-secret, domain||value)",
                "locator_keying": key.keying,
            },
            "secrets_scan": secrets_scan,
            "schema_set": "schemas/wiring/v1",
        },
        "subjects": subjects,
    }
    manifest_path = wiring / "wiring-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest_doc, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        f"wiring_emit: {len(files)} artifacts + manifest -> {wiring}",
        file=sys.stderr,
    )
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Emit the wiring corpus for one host from a DK manifest"
    )
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--host", required=True)
    parser.add_argument(
        "--collection-mode",
        default="live",
        choices=["live", "offline-staged"],
    )
    parser.add_argument(
        "--locator-key-env",
        default="RB_WIRING_LOCATOR_KEY",
        help="env var holding the locator key (default RB_WIRING_LOCATOR_KEY)",
    )
    parser.add_argument("--locator-key-file", default=None)
    parser.add_argument("--insecure-unkeyed-locators", action="store_true")
    args = parser.parse_args(argv)

    return emit_corpus(
        manifest_path=args.manifest,
        output_dir=args.output_dir,
        host=args.host,
        collection_mode=args.collection_mode,
        locator_key_env=args.locator_key_env,
        locator_key_file=args.locator_key_file,
        insecure_unkeyed=args.insecure_unkeyed_locators,
    )


if __name__ == "__main__":
    sys.exit(main())
