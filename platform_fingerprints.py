#!/usr/bin/env python3
"""ci/lib/platform_fingerprints.py

S42-06: complete platform-file inventory for one JBoss home, emitted as
platform-fingerprints.json (schemas/wiring/v1/platform-fingerprints.
schema.json).

Unlike the DK pack's fingerprints.json — a suffix-filtered subset
(instance config + deployment archives) — this is the FULL platform
layer: every jar, every module.xml descriptor, bin/, server/lib,
.overlays. It is also the standalone "one-command PROD pull": run it
against any readable JBOSS_HOME (live or staged) and the output upgrades
an offline platform layer to verified-copy when the real PROD listing
arrives (consumed by the Sprint 41 assembler's layer-confidence logic).

Scan roots (relative to --jboss-home):
    modules/   .overlays/   bin/   server/lib/   appclient/   docs/schema/

Unreadable files are counted and reported — never silently skipped
(truncated=false is required for verified-copy claims; --max-files
guards pathological trees and sets truncated=true when tripped).

Deterministic: files sorted by path; no timestamps.

Usage:
    platform_fingerprints.py --host HOST --jboss-home DIR \
        [--collection-mode live|offline-staged] [--max-files N] \
        --out FILE        (or '-' for stdout)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

SCAN_ROOTS = (
    "modules",
    ".overlays",
    "bin",
    "server/lib",
    "appclient",
    "docs/schema",
)

KIND_BY_SUFFIX = {
    ".jar": "jar",
    ".so": "native-lib",
    ".dll": "native-lib",
    ".dylib": "native-lib",
    ".sh": "script",
    ".bat": "script",
    ".xml": "config",
    ".properties": "config",
}

DEFAULT_MAX_FILES = 50000


def sha256_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def scan(jboss_home: Path, max_files: int):
    files: list[dict] = []
    unreadable = 0
    truncated = False
    seen_roots = []
    total = 0
    for root_rel in SCAN_ROOTS:
        root = jboss_home / root_rel
        if not root.is_dir():
            continue
        seen_roots.append(root_rel)
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()
            for name in sorted(filenames):
                total += 1
                if total > max_files:
                    truncated = True
                    break
                p = Path(dirpath) / name
                if p.is_symlink() or not p.is_file():
                    continue
                relpath = p.relative_to(jboss_home).as_posix()
                try:
                    digest = sha256_file(p)
                    size = p.stat().st_size
                except OSError:
                    unreadable += 1
                    continue
                suffix = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
                if name == "module.xml":
                    kind = "module-descriptor"
                else:
                    kind = KIND_BY_SUFFIX.get(suffix, "other")
                files.append(
                    {
                        "path": relpath,
                        "sha256": digest,
                        "size": size,
                        "kind": kind,
                    }
                )
            if truncated:
                break
        if truncated:
            break
    files.sort(key=lambda f: f["path"])
    counts = {
        "total": len(files),
        "jars": sum(1 for f in files if f["kind"] == "jar"),
        "module_descriptors": sum(
            1 for f in files if f["kind"] == "module-descriptor"
        ),
        "unreadable": unreadable,
    }
    return files, counts, seen_roots, truncated


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Emit platform-fingerprints.json for one JBoss home"
    )
    parser.add_argument("--host", required=True)
    parser.add_argument("--jboss-home", required=True, type=Path)
    parser.add_argument(
        "--collection-mode",
        default="offline-staged",
        choices=["live", "offline-staged"],
    )
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    parser.add_argument("--out", required=True, help="output path or '-' for stdout")
    args = parser.parse_args(argv)

    jboss_home = args.jboss_home.resolve()
    if not jboss_home.is_dir():
        print(f"ERROR: jboss-home not found: {jboss_home}", file=sys.stderr)
        return 1

    files, counts, seen_roots, truncated = scan(jboss_home, args.max_files)
    document = {
        "schema_version": "1",
        "artifact": "platform-fingerprints",
        "subject": {
            "host": args.host,
            "jboss_home": str(jboss_home),
            "collection_mode": args.collection_mode,
        },
        "scan_roots": seen_roots,
        "files": files,
        "counts": counts,
        "truncated": truncated,
    }
    payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.out == "-":
        sys.stdout.write(payload)
    else:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(payload, encoding="utf-8")
        print(
            f"platform-fingerprints: {counts['total']} files "
            f"({counts['jars']} jars, {counts['module_descriptors']} "
            f"descriptors, {counts['unreadable']} unreadable) -> {out}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
