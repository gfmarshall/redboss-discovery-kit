#!/usr/bin/env python3
"""ci/lib/server_roots.py

S42-05: derive server-level wiring for one JBoss instance config file
and emit server-roots.json conforming to schemas/wiring/v1/
server-roots.schema.json (ADR-0019).

Extracted (namespace-agnostic over urn:jboss:domain:*):

  - <extensions>/<extension>            -> extensions[]  (the implicit-
                                            dependency gating surface)
  - <profile>/<subsystem>               -> subsystems[]  (name from xmlns)
  - ee subsystem <global-modules>       -> ee_global_modules[]
  - <socket-binding-group>              -> socket_binding_groups[]
    (socket/outbound/remote-destination bindings; multicast + remote
    destinations -> locator hashes, never clear)
  - <interfaces>                        -> interfaces[]  (resolved address
    criteria -> locator hashes)
  - <system-properties>                 -> classified: structural clear /
    locator keyed-hash / secret-shaped REDACTED
  - deployment-scanner subsystem        -> deployment_scanners[]
    (absent under the hardened profile — itself a gating signal)
  - <deployments> section               -> managed_deployments flag
    (content-repository deployments bypass descriptor extraction —
    flagged, never silently thin)

XML comments are ignored by construction. Deterministic: every array
sorted; no timestamps.

Usage:
    server_roots.py --host HOST --jboss-home DIR --instance NAME \
        --config PATH [--collection-mode live|offline-staged] \
        [--locator-key-file PATH | --insecure-unkeyed-locators] \
        --out FILE

Locator key resolution: --locator-key-file, then $RB_WIRING_LOCATOR_KEY,
else --insecure-unkeyed-locators (dev/test; declared 'unkeyed' in the
manifest attestation).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from wiring_classify import (  # noqa: E402
    LocatorKey,
    classify_property,
    is_locator_shaped,
)

SUBSYSTEM_NS_RE = re.compile(r"urn:(?:jboss:domain|wildfly):([^:]+):")
PORT_EXPR_RE = re.compile(r":(\d+)\}\s*$")


def localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def ns_of(tag: str) -> str:
    return tag[1:].split("}")[0] if tag.startswith("{") else ""


def bool_attr(element: ET.Element, name: str, default: bool = False) -> bool:
    raw = element.get(name)
    return default if raw is None else raw.strip().lower() == "true"


def int_or_expr_default(raw: str | None) -> int | None:
    if raw is None:
        return None
    raw = raw.strip()
    if raw.isdigit():
        return int(raw)
    m = PORT_EXPR_RE.search(raw)
    return int(m.group(1)) if m else None


def children(element: ET.Element, name: str):
    return [c for c in element if localname(c.tag) == name]


def extract(root: ET.Element, key: LocatorKey) -> dict:
    out = {
        "extensions": [],
        "subsystems": [],
        "ee_global_modules": [],
        "socket_binding_groups": [],
        "interfaces": [],
        "system_properties": [],
        "deployment_scanners": [],
        "managed_deployments": {"present": False},
        "parse_errors": [],
    }

    def walk(element: ET.Element):
        yield element
        for child in element:
            yield from walk(child)

    for el in walk(root):
        tag = localname(el.tag)
        if tag == "extension" and el.get("module"):
            out["extensions"].append({"module": el.get("module").strip()})
        elif tag == "subsystem":
            xmlns = ns_of(el.tag)
            m = SUBSYSTEM_NS_RE.search(xmlns)
            out["subsystems"].append(
                {"name": m.group(1) if m else xmlns, "xmlns": xmlns}
            )
            for gm in children(el, "global-modules"):
                for mod in children(gm, "module"):
                    entry = {"name": mod.get("name", "").strip()}
                    if mod.get("slot"):
                        entry["slot"] = mod.get("slot").strip()
                    if bool_attr(mod, "annotations"):
                        entry["annotations"] = True
                    services = (mod.get("services") or "").strip()
                    if services:
                        entry["services"] = services
                    meta_inf = (mod.get("meta-inf") or "").strip()
                    if meta_inf:
                        entry["meta_inf"] = meta_inf
                    if entry["name"]:
                        out["ee_global_modules"].append(entry)
            for ds in children(el, "deployment-scanner"):
                scanner = {
                    "name": (ds.get("name") or "default").strip(),
                    "path_locator": key.hash(
                        "scanner-path", ds.get("path", "")
                    ),
                    "scan_enabled": bool_attr(ds, "scan-enabled", True),
                }
                for attr, field in (
                    ("scan-interval", "scan_interval"),
                    ("deployment-timeout", "deployment_timeout"),
                ):
                    val = int_or_expr_default(ds.get(attr))
                    if val is not None:
                        scanner[field] = val
                for attr, field in (
                    ("auto-deploy-exploded", "auto_deploy_exploded"),
                    ("auto-deploy-zipped", "auto_deploy_zipped"),
                ):
                    if ds.get(attr) is not None:
                        scanner[field] = bool_attr(ds, attr)
                if ds.get("relative-to"):
                    scanner["relative_to"] = ds.get("relative-to")
                out["deployment_scanners"].append(scanner)
        elif tag == "socket-binding-group":
            group = {
                "name": (el.get("name") or "standard-sockets").strip(),
                "bindings": [],
            }
            if el.get("default-interface"):
                group["default_interface"] = el.get("default-interface")
            for b in el:
                btag = localname(b.tag)
                if btag == "socket-binding" and b.get("name"):
                    binding = {
                        "name": b.get("name").strip(),
                        "type": "socket-binding",
                    }
                    port = int_or_expr_default(b.get("port"))
                    binding["port"] = port
                    if b.get("interface"):
                        binding["interface"] = b.get("interface")
                    if b.get("fixed-port") is not None:
                        binding["fixed_port"] = bool_attr(b, "fixed-port")
                    mc = [
                        b.get("multicast-address") or "",
                        b.get("multicast-port") or "",
                    ]
                    if any(mc):
                        binding["multicast_locator"] = key.hash(
                            "socket-multicast", ":".join(mc)
                        )
                    group["bindings"].append(binding)
                elif btag in (
                    "outbound-socket-binding",
                    "remote-destination-outbound-socket-binding",
                ) and b.get("name"):
                    binding = {
                        "name": b.get("name").strip(),
                        "type": btag,
                    }
                    dest_parts = []
                    for sub in b:
                        if localname(sub.tag) == "remote-destination":
                            dest_parts.append(
                                f"{sub.get('host','')}:{sub.get('port','')}"
                            )
                    if b.get("host") or b.get("port"):
                        dest_parts.append(
                            f"{b.get('host','')}:{b.get('port','')}"
                        )
                    if dest_parts:
                        binding["destination_locator"] = key.hash(
                            "socket-dest", "|".join(sorted(dest_parts))
                        )
                    group["bindings"].append(binding)
            group["bindings"].sort(key=lambda b: b["name"])
            out["socket_binding_groups"].append(group)
        elif tag == "interface" and el.get("name"):
            criteria = []
            for sub in el:
                stag = localname(sub.tag)
                val = sub.get("value") or sub.get("name") or ""
                criteria.append(
                    f"{stag}:{val}" if val else stag
                )
            canonical = "|".join(sorted(criteria)) or "unspecified"
            out["interfaces"].append(
                {
                    "name": el.get("name").strip(),
                    "locator": key.hash("interface", canonical),
                }
            )
        elif tag == "system-properties":
            for prop in children(el, "property"):
                if not prop.get("name"):
                    continue
                name = prop.get("name").strip()
                value = prop.get("value") or ""
                cls, emitted = classify_property(name, value)
                if cls == "unclassified":
                    if is_locator_shaped(value):
                        cls, emitted = "locator", key.hash("sysprop", value)
                    else:
                        cls, emitted = "structural", value
                out["system_properties"].append(
                    {"name": name, "class": cls, "value": emitted}
                )
        elif tag == "deployments":
            names = [
                d.get("name", "").strip()
                for d in el
                if localname(d.tag) == "deployment" and d.get("name")
            ]
            out["managed_deployments"] = {
                "present": True,
                "count": len(names),
                "names": sorted(names),
            }

    for field in ("extensions", "subsystems", "ee_global_modules",
                  "interfaces", "system_properties", "deployment_scanners"):
        key_name = "module" if field == "extensions" else "name"
        out[field].sort(key=lambda e: e.get(key_name, ""))
    out["socket_binding_groups"].sort(key=lambda g: g["name"])
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Emit server-roots.json for one instance config"
    )
    parser.add_argument("--host", required=True)
    parser.add_argument("--jboss-home", required=True, type=Path)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--locator-key-file", default=None)
    parser.add_argument(
        "--insecure-unkeyed-locators",
        action="store_true",
        help="dev/test only: fixed domain key; attestation records unkeyed",
    )
    parser.add_argument(
        "--collection-mode",
        default="offline-staged",
        choices=["live", "offline-staged"],
    )
    parser.add_argument("--out", required=True, help="output path or '-' for stdout")
    args = parser.parse_args(argv)

    jboss_home = args.jboss_home.resolve()
    config = args.config.resolve()
    if not config.is_file():
        print(f"ERROR: config not found: {config}", file=sys.stderr)
        return 1
    key = LocatorKey.resolve(args.locator_key_file, args.insecure_unkeyed_locators)
    if key.keying == "unkeyed":
        print(
            "WARNING: unkeyed locators — engagement scoping absent (dev/test)",
            file=sys.stderr,
        )

    try:
        config_rel = config.relative_to(jboss_home).as_posix()
    except ValueError:
        config_rel = str(config)
    try:
        root = ET.parse(config).getroot()
    except ET.ParseError as exc:
        print(f"ERROR: malformed config XML: {exc}", file=sys.stderr)
        return 1

    extracted = extract(root, key)
    document = {
        "schema_version": "1",
        "artifact": "server-roots",
        "subject": {
            "host": args.host,
            "jboss_home": str(jboss_home),
            "instance": args.instance,
            "config_path": config_rel,
            "collection_mode": args.collection_mode,
        },
        **extracted,
    }
    payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.out == "-":
        sys.stdout.write(payload)
    else:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(payload, encoding="utf-8")
        print(
            f"server-roots: {len(extracted['extensions'])} extensions, "
            f"{len(extracted['subsystems'])} subsystems, "
            f"{len(extracted['system_properties'])} sysprops "
            f"(locator_keying={key.keying}) -> {out}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
