#!/usr/bin/env python3
"""ci/lib/module_graph.py

S42-03: derive the platform module dependency graph for one JBoss home
and emit module-graph.json conforming to schemas/wiring/v1/
module-graph.schema.json (ADR-0019 — derived metadata only, never file
bodies).

Scans every module descriptor reachable under the JBoss home:

  - modules/                     (direct children -> layer 'base')
  - modules/system/layers/*/     (EAP 7 layering)
  - modules/system/add-ons/*/    (installed add-ons)
  - .overlays/*/                 (patched overlay descriptors)
  - server/lib/                  (legacy server libs, if present)

XML comments are ignored by construction (ElementTree drops them).
Jandex indexes inside resource roots do not alter the graph — they are
marker signals consumed by the deployment marker scan, not module
wiring.

Deterministic output: modules sorted by (name, slot), dependencies by
(name, slot), resource_roots by path, system_dependencies by paths.
No timestamps — the wiring-manifest carries generation time.

Usage:
    module_graph.py --host HOST --jboss-home DIR \
        [--jboss-version VER] [--collection-mode live|offline-staged] \
        --out FILE        (or '-' for stdout)

Exit 0 = emitted; nonzero = unusable input. Modules that fail to parse
still appear with recoverable fields plus a parse_errors entry — partial
data is flagged, never silently dropped.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

PROPERTIES_ALLOWLIST = {"jboss.api", "jboss.api-private", "jboss.api-deprecated"}


def sha256_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def layer_of(module_xml: Path, jboss_home: Path) -> str:
    """Classify the descriptor's owning layer from its path shape."""
    parts = module_xml.relative_to(jboss_home).parts
    for i, part in enumerate(parts[:-1]):
        if part == "layers" and i + 1 < len(parts) - 1:
            return parts[i + 1]
        if part == "add-ons" and i + 1 < len(parts) - 1:
            return f"add-on:{parts[i + 1]}"
    if parts[0] == ".overlays" and len(parts) > 1:
        return f"overlay:{parts[1]}"
    return "base"


def localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def bool_attr(element: ET.Element, name: str, default: bool = False) -> bool:
    raw = element.get(name)
    return default if raw is None else raw.strip().lower() == "true"


def parse_module_xml(descriptor: Path, module_dir: Path, jboss_home: Path):
    """Parse one module.xml; return (module_dict, error_dict|None)."""
    error = None
    module = {
        "name": "",
        "slot": "main",
        "descriptor": {
            "path": rel(descriptor, jboss_home),
            "sha256": sha256_file(descriptor),
            "layer": layer_of(descriptor, jboss_home),
        },
        "properties": {},
        "resource_roots": [],
        "dependencies": [],
        "system_dependencies": [],
    }
    try:
        tree = ET.parse(descriptor)
    except ET.ParseError:
        error = {"path": module["descriptor"]["path"], "error_class": "malformed-xml"}
        return module, error
    except (OSError, UnicodeError):
        error = {"path": module["descriptor"]["path"], "error_class": "io"}
        return module, error

    root = tree.getroot()
    if localname(root.tag) == "module-alias":
        # <module-alias> is a pure name redirect — return it via the
        # aliases channel, not as a module or an error (EAP 7.3 uses
        # these heavily for javax->jakarta renames).
        alias = {
            "name": (root.get("name") or "").strip(),
            "target": (root.get("target-name") or "").strip(),
            "target_slot": (root.get("target-slot") or "main").strip() or "main",
            "descriptor": module["descriptor"],
        }
        return {"__alias__": alias}, None
    if localname(root.tag) != "module":
        error = {"path": module["descriptor"]["path"], "error_class": "schema"}
        return module, error

    module["name"] = (root.get("name") or "").strip()
    slot = (root.get("slot") or "main").strip()
    module["slot"] = slot or "main"

    for child in root:
        tag = localname(child.tag)
        if tag == "properties":
            for prop in child:
                if (
                    localname(prop.tag) == "property"
                    and prop.get("name") in PROPERTIES_ALLOWLIST
                ):
                    module["properties"][prop.get("name")] = (
                        prop.get("value") or ""
                    )
        elif tag == "resources":
            for res in child:
                if localname(res.tag) != "resource-root":
                    continue
                rpath = (res.get("path") or "").strip()
                if not rpath:
                    continue
                target = (module_dir / rpath).resolve() if rpath != "." else module_dir
                if target.is_dir() or rpath in (".", ""):
                    kind = "dir"
                elif rpath.lower().endswith(".jar"):
                    kind = "jar"
                else:
                    kind = "other"
                entry = {"path": rpath, "kind": kind}
                present = target.is_file() or (kind == "dir" and target.is_dir())
                entry["present"] = present
                if present and target.is_file():
                    entry["sha256"] = sha256_file(target)
                    entry["size"] = target.stat().st_size
                module["resource_roots"].append(entry)
        elif tag == "dependencies":
            for dep in child:
                dtag = localname(dep.tag)
                if dtag == "module":
                    name = (dep.get("name") or "").strip()
                    if not name:
                        continue
                    module["dependencies"].append(
                        {
                            "name": name,
                            "slot": (dep.get("slot") or "main").strip() or "main",
                            "export": bool_attr(dep, "export"),
                            "services": (dep.get("services") or "none").strip() or "none",
                            "optional": bool_attr(dep, "optional"),
                        }
                    )
                elif dtag == "system":
                    paths = []
                    for paths_el in dep:
                        if localname(paths_el.tag) != "paths":
                            continue
                        for p in paths_el:
                            if localname(p.tag) == "path" and p.get("name"):
                                paths.append(p.get("name"))
                    module["system_dependencies"].append(
                        {"paths": sorted(paths), "export": bool_attr(dep, "export")}
                    )
                # <local-loader>, <imports>/<exports> filters: v2 fidelity
    if not module["name"]:
        error = {"path": module["descriptor"]["path"], "error_class": "schema"}
    module["resource_roots"].sort(key=lambda r: r["path"])
    module["dependencies"].sort(key=lambda d: (d["name"], d["slot"]))
    module["system_dependencies"].sort(key=lambda s: ",".join(s["paths"]))
    return module, error


def scan(jboss_home: Path) -> tuple[list[dict], list[dict], list[dict]]:
    modules: list[dict] = []
    aliases: list[dict] = []
    errors: list[dict] = []
    roots = [
        jboss_home / "modules",
        jboss_home / ".overlays",
        jboss_home / "server" / "lib",
    ]
    for scan_root in roots:
        if not scan_root.is_dir():
            continue
        for descriptor in sorted(scan_root.rglob("module.xml")):
            if descriptor.is_symlink() or not descriptor.is_file():
                continue
            module, error = parse_module_xml(
                descriptor, descriptor.parent, jboss_home
            )
            if "__alias__" in module:
                aliases.append(module["__alias__"])
            else:
                modules.append(module)
            if error:
                errors.append(error)
    modules.sort(key=lambda m: (m["name"], m["slot"]))
    aliases.sort(key=lambda a: (a["name"], a["target"], a["target_slot"]))
    errors.sort(key=lambda e: e["path"])
    return modules, aliases, errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Emit module-graph.json for one JBoss home"
    )
    parser.add_argument("--host", required=True)
    parser.add_argument("--jboss-home", required=True, type=Path)
    parser.add_argument("--jboss-version", default=None)
    parser.add_argument(
        "--collection-mode",
        default="offline-staged",
        choices=["live", "offline-staged"],
    )
    parser.add_argument("--out", required=True, help="output path or '-' for stdout")
    args = parser.parse_args(argv)

    jboss_home = args.jboss_home.resolve()
    if not jboss_home.is_dir():
        print(f"ERROR: jboss-home not found: {jboss_home}", file=sys.stderr)
        return 1

    modules, aliases, errors = scan(jboss_home)
    subject = {
        "host": args.host,
        "jboss_home": str(jboss_home),
        "collection_mode": args.collection_mode,
    }
    if args.jboss_version:
        subject["jboss_version_asserted"] = args.jboss_version

    document = {
        "schema_version": "1",
        "artifact": "module-graph",
        "subject": subject,
        "modules": modules,
        "aliases": aliases,
        "parse_errors": errors,
    }
    payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.out == "-":
        sys.stdout.write(payload)
    else:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(payload, encoding="utf-8")
        print(
            f"module-graph: {len(modules)} modules, {len(aliases)} aliases, "
            f"{len(errors)} parse errors -> {out}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
