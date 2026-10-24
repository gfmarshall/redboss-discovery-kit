#!/usr/bin/env python3
"""ci/lib/deploy_wiring.py

S42-04: derive per-deployment wiring for one JBoss instance and emit
deployment-wiring.json conforming to schemas/wiring/v1/
deployment-wiring.schema.json (ADR-0019 — derived metadata only, never
file bodies).

Per deployment under the deployments dir (exploded dirs and packed
.war/.ear/.jar/.rar alike):

  - META-INF/MANIFEST.MF         -> Dependencies:, Class-Path:,
                                  Implementation-*/Build-*/Specification-*
                                  attributes (allowlist)
  - WEB-INF|/META-INF/jboss-deployment-structure.xml
                                -> module deps, system deps, exclusions,
                                   exclude-subsystems, local-resources,
                                   sub-deployments, ear isolation
  - WEB-INF/jboss-web.xml       -> context-root, security-domain name,
                                  virtual-host
  - WEB-INF/lib + EAR lib/      -> jar inventory (sha256 + size)
  - marker files                -> implicit-dependency triggers for the
                                  Sprint 43 KB (any observed marker with no
                                  KB rule flags unmodelled_trigger there)
  - EAR members / rar etc.      -> nested_archives (recorded, not recursed)

Packed archives are parsed in-memory via zipfile — member bytes are
read only to hash or to parse descriptors; nothing is extracted to
disk, and no archive bytes are emitted.

XML comments are ignored by construction (ElementTree drops them).
Deterministic output: deployments sorted by name, every list sorted.
No timestamps — the wiring-manifest carries generation time.

Usage:
    deploy_wiring.py --host HOST --jboss-home DIR --instance NAME \
        --deployments-dir DIR [--managed-names n1,n2] \
        [--collection-mode live|offline-staged] --out FILE
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

ARCHIVE_SUFFIXES = {".war", ".ear", ".jar", ".rar"}
NESTED_SUFFIXES = {".war", ".jar", ".rar", ".par", ".sar"}

MANIFEST_ATTR_ALLOWLIST_PREFIXES = ("Build-", "Specification-")
MANIFEST_ATTR_ALLOWLIST_EXACT = {
    "Implementation-Title",
    "Implementation-Version",
    "Implementation-Vendor-Id",
}

# Broad trigger-file set: the KB (S43-02) resolves these; anything observed
# but unmodelled flags unmodelled_trigger — never silently ignored.
MARKER_BASENAMES = {
    "web.xml",
    "web-fragment.xml",
    "beans.xml",
    "persistence.xml",
    "orm.xml",
    "faces-config.xml",
    "taglib.tld",
    "ejb-jar.xml",
    "jboss-ejb3.xml",
    "application.xml",
    "jboss-app.xml",
    "application-client.xml",
    "jboss-service.xml",
    "ra.xml",
    "webservices.xml",
    "jaxws-catalog.xml",
    "jboss-webservices.xml",
    "struts.xml",
    "validation.xml",
    "jandex.idx",
    "log4j.xml",
    "log4j2.xml",
    "picketlink.xml",
}
MARKER_PREFIXES = (
    "META-INF/services/",
    "WEB-INF/classes/META-INF/services/",
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def bool_attr(element: ET.Element, name: str, default: bool = False) -> bool:
    raw = element.get(name)
    return default if raw is None else raw.strip().lower() == "true"


class DeploymentSource:
    """Unified read view over an exploded dir or a packed archive."""

    def __init__(self, path: Path):
        self.path = path
        self.form = "exploded" if path.is_dir() else "packed"
        self._zip = None
        self._names: list[str] | None = None
        if self.form == "packed":
            self._zip = zipfile.ZipFile(path)
            self._names = sorted(
                i.filename for i in self._zip.infolist() if not i.is_dir()
            )

    def names(self) -> list[str]:
        if self._names is not None:
            return self._names
        out: list[str] = []
        for root, dirs, files in os.walk(self.path):
            dirs.sort()
            for f in sorted(files):
                p = Path(root) / f
                if p.is_symlink():
                    continue
                out.append(p.relative_to(self.path).as_posix())
        self._names = sorted(out)
        return self._names

    def exists(self, rel: str) -> bool:
        return rel in self.names()

    def read(self, rel: str) -> bytes | None:
        if self.form == "packed":
            try:
                return self._zip.read(rel)
            except KeyError:
                return None
        p = self.path / rel
        return p.read_bytes() if p.is_file() else None

    def file_entry(self, rel: str) -> dict | None:
        if self.form == "packed":
            info = next(
                (i for i in self._zip.infolist() if i.filename == rel), None
            )
            if info is None:
                return None
            return {
                "path": rel,
                "sha256": sha256_bytes(self._zip.read(rel)),
                "size": info.file_size,
            }
        p = self.path / rel
        if not p.is_file():
            return None
        return {"path": rel, "sha256": sha256_file(p), "size": p.stat().st_size}

    def close(self):
        if self._zip is not None:
            self._zip.close()


def parse_manifest(data: bytes) -> dict:
    """Java manifest: headers until first blank line; continuation lines
    begin with a single space (JAR spec 72-byte folding)."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")
    headers: dict[str, str] = {}
    current = None
    for line in text.replace("\r\n", "\n").split("\n"):
        if line == "":
            break  # end of main section
        if line.startswith(" ") and current is not None:
            headers[current] += line[1:]
            continue
        if ":" in line:
            name, _, value = line.partition(":")
            current = name.strip()
            headers[current] = value.strip()
        else:
            current = None
    return headers


def manifest_dependencies(raw: str) -> tuple[list[dict], list[str]]:
    """JBoss MANIFEST Dependencies: comma-separated entries, each
    'name[:slot] [export] [services] [optional] ...'. Unknown flag tokens
    are surfaced, not silently dropped."""
    deps: list[dict] = []
    unknown: list[str] = []
    for entry in raw.split(","):
        tokens = entry.split()
        if not tokens:
            continue
        head = tokens[0]
        name, _, slot = head.partition(":")
        dep = {
            "name": name,
            "slot": slot or "main",
            "export": False,
            "services": "none",
            "optional": False,
        }
        for tok in tokens[1:]:
            if tok == "export":
                dep["export"] = True
            elif tok == "services":
                dep["services"] = "import"
            elif tok == "optional":
                dep["optional"] = True
            else:
                unknown.append(tok)
        deps.append(dep)
    deps.sort(key=lambda d: (d["name"], d["slot"]))
    return deps, unknown


def parse_deployment_structure(data: bytes, rel: str, errors: list) -> dict:
    out = {
        "present": True,
        "path": rel,
        "dependencies": [],
        "system_dependencies": [],
        "exclusions": [],
        "exclude_subsystems": [],
        "local_resources": [],
        "sub_deployments": [],
    }

    def deps_of(container: ET.Element, target: dict):
        # namespace-agnostic: deployment-structure uses versioned xmlns
        # (urn:jboss:deployment-structure:1.x) — match on local names.
        for child in container:
            if localname(child.tag) != "dependencies":
                continue
            for el in child:
                tag = localname(el.tag)
                if tag == "module" and el.get("name"):
                    target["dependencies"].append(
                        {
                            "name": el.get("name").strip(),
                            "slot": (el.get("slot") or "main").strip() or "main",
                            "export": bool_attr(el, "export"),
                            "services": (el.get("services") or "none").strip()
                            or "none",
                            "optional": bool_attr(el, "optional"),
                        }
                    )
                elif tag == "system":
                    paths = []
                    for paths_el in el:
                        if localname(paths_el.tag) != "paths":
                            continue
                        for p in paths_el:
                            if localname(p.tag) == "path" and p.get("name"):
                                paths.append(p.get("name"))
                    target["system_dependencies"].append(
                        {"paths": sorted(paths), "export": bool_attr(el, "export")}
                    )
        for child in container:
            tag = localname(child.tag)
            if tag in ("exclusions", "exclude-subsystems"):
                names = [
                    el.get("name")
                    for el in child
                    if el.get("name")
                ]
                key = "exclusions" if tag == "exclusions" else "exclude_subsystems"
                target[key].extend(names)
            elif tag in ("local-resources", "resources"):
                for el in child:
                    if localname(el.tag) == "resource-root" and el.get("path"):
                        target["local_resources"].append(el.get("path"))

    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        errors.append({"path": rel, "error_class": "malformed-xml"})
        return out
    if localname(root.tag) != "jboss-deployment-structure":
        errors.append({"path": rel, "error_class": "other", "detail": "unexpected root element"})
        return out

    for child in root:
        tag = localname(child.tag)
        if tag == "ear-subdeployments-isolated":
            out["ear_subdeployments_isolated"] = (
                (child.text or "").strip().lower() == "true"
            )
        elif tag == "deployment":
            deps_of(child, out)
            for sub in child:
                if localname(sub.tag) == "ear-subdeployments-isolated":
                    out["ear_subdeployments_isolated"] = (
                        (sub.text or "").strip().lower() == "true"
                    )
        elif tag == "sub-deployment":
            sub = {
                "name": (child.get("name") or "?").strip(),
                "dependencies": [],
                "system_dependencies": [],
                "exclusions": [],
                "local_resources": [],
            }
            deps_of(child, sub)
            for key in ("dependencies", "exclusions", "local_resources"):
                sub[key].sort()
            sub["dependencies"].sort(key=lambda d: (d["name"], d["slot"]))
            sub["system_dependencies"].sort(
                key=lambda s: ",".join(s["paths"])
            )
            out["sub_deployments"].append(sub)

    out["dependencies"].sort(key=lambda d: (d["name"], d["slot"]))
    out["system_dependencies"].sort(key=lambda s: ",".join(s["paths"]))
    for key in ("exclusions", "exclude_subsystems", "local_resources"):
        out[key] = sorted(set(out[key]))
    out["sub_deployments"].sort(key=lambda s: s["name"])
    return out


def parse_jboss_web(data: bytes, rel: str, errors: list) -> dict:
    out = {"present": True, "path": rel}
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        errors.append({"path": rel, "error_class": "malformed-xml"})
        return out
    for child in root:
        tag = localname(child.tag)
        text = (child.text or "").strip()
        if tag == "context-root" and text:
            out["context_root"] = text
        elif tag == "security-domain" and text:
            out["security_domain"] = text
        elif tag == "virtual-host" and text:
            out["virtual_host"] = text
    return out


def markers_of(names: list[str]) -> list[str]:
    markers = set()
    for name in names:
        base = name.rsplit("/", 1)[-1]
        if base in MARKER_BASENAMES:
            markers.add(name)
            continue
        for prefix in MARKER_PREFIXES:
            if name.startswith(prefix) and len(name) > len(prefix):
                markers.add(name)
                break
    return sorted(markers)


def nested_archives_of(names: list[str], form_hint: str) -> list[str]:
    out = set()
    for name in names:
        suffix = Path(name).suffix.lower()
        if suffix not in NESTED_SUFFIXES:
            continue
        if name.startswith("WEB-INF/lib/") or name.startswith("lib/"):
            continue  # lib inventory handles these
        depth = name.count("/")
        if form_hint == "ear" and depth == 0:
            out.add(name)  # EAR member archive
        elif suffix in {".rar", ".par", ".sar"}:
            out.add(name)
    return sorted(out)


def is_ear(names: list[str]) -> bool:
    return "META-INF/application.xml" in names or any(
        n.endswith(".war") and n.count("/") == 0 for n in names
    )


def process_deployment(path: Path, name: str, managed: bool) -> dict:
    errors: list[dict] = []
    deployment = {
        "name": name,
        "root": path.name,
        "form": "managed" if managed else ("exploded" if path.is_dir() else "packed"),
        "archive_sha256": sha256_file(path) if path.is_file() else None,
        "manifest": {"present": False},
        "jboss_deployment_structure": {"present": False},
        "jboss_web": {"present": False},
        "lib": [],
        "markers": [],
        "nested_archives": [],
        "parse_errors": errors,
    }
    if managed:
        return deployment

    try:
        source = DeploymentSource(path)
    except zipfile.BadZipFile:
        errors.append(
            {"path": path.name, "error_class": "other", "detail": "unreadable archive"}
        )
        return deployment

    names = source.names()

    manifest_rel = "META-INF/MANIFEST.MF"
    if source.exists(manifest_rel):
        data = source.read(manifest_rel)
        headers = parse_manifest(data or b"")
        manifest = {
            "present": True,
            "path": manifest_rel,
            "dependencies": [],
            "class_path": [],
            "build_attributes": {},
        }
        if "Dependencies" in headers:
            deps, unknown = manifest_dependencies(headers["Dependencies"])
            manifest["dependencies"] = deps
            if unknown:
                errors.append(
                    {
                        "path": manifest_rel,
                        "error_class": "other",
                        "detail": f"unrecognised Dependencies tokens: {sorted(set(unknown))[:5]}",
                    }
                )
        if "Class-Path" in headers:
            manifest["class_path"] = sorted(headers["Class-Path"].split())
        for key, value in headers.items():
            if key in MANIFEST_ATTR_ALLOWLIST_EXACT:
                if key == "Implementation-Title":
                    manifest["implementation_title"] = value
                elif key == "Implementation-Version":
                    manifest["implementation_version"] = value
                elif key == "Implementation-Vendor-Id":
                    manifest["implementation_vendor_id"] = value
            elif key.startswith(MANIFEST_ATTR_ALLOWLIST_PREFIXES):
                manifest["build_attributes"][key] = value
        deployment["manifest"] = manifest

    for rel in (
        "WEB-INF/jboss-deployment-structure.xml",
        "META-INF/jboss-deployment-structure.xml",
    ):
        if source.exists(rel):
            data = source.read(rel)
            deployment["jboss_deployment_structure"] = (
                parse_deployment_structure(data or b"", rel, errors)
            )
            break

    if source.exists("WEB-INF/jboss-web.xml"):
        data = source.read("WEB-INF/jboss-web.xml")
        deployment["jboss_web"] = parse_jboss_web(data or b"", "WEB-INF/jboss-web.xml", errors)

    ear = path.suffix.lower() == ".ear" or is_ear(names)
    lib_entries = []
    for n in names:
        if n.startswith("WEB-INF/lib/") and n.endswith(".jar"):
            lib_entries.append(source.file_entry(n))
        elif ear and n.startswith("lib/") and n.endswith(".jar"):
            lib_entries.append(source.file_entry(n))
    deployment["lib"] = sorted(
        [e for e in lib_entries if e], key=lambda e: e["path"]
    )
    deployment["markers"] = markers_of(names)
    deployment["nested_archives"] = nested_archives_of(
        names, "ear" if ear else "war"
    )
    source.close()
    return deployment


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Emit deployment-wiring.json for one instance's deployments"
    )
    parser.add_argument("--host", required=True)
    parser.add_argument("--jboss-home", required=True, type=Path)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--deployments-dir", required=True, type=Path)
    parser.add_argument("--managed-names", default="")
    parser.add_argument(
        "--collection-mode",
        default="offline-staged",
        choices=["live", "offline-staged"],
    )
    parser.add_argument("--out", required=True, help="output path or '-' for stdout")
    args = parser.parse_args(argv)

    deployments_dir = args.deployments_dir.resolve()
    if not deployments_dir.is_dir():
        print(
            f"ERROR: deployments dir not found: {deployments_dir}",
            file=sys.stderr,
        )
        return 1
    managed = {n.strip() for n in args.managed_names.split(",") if n.strip()}

    deployments: list[dict] = []
    for entry in sorted(deployments_dir.iterdir()):
        name = entry.name
        if name.startswith(".") or name.endswith((".dodeploy", ".deployed", ".failed", ".isdeploying", ".isundeploying", ".pending", ".undeployed", ".skipdeploy")):
            continue
        if entry.is_dir():
            deployments.append(process_deployment(entry, name, name in managed))
        elif entry.suffix.lower() in ARCHIVE_SUFFIXES:
            deployments.append(process_deployment(entry, name, name in managed))
    deployments.sort(key=lambda d: d["name"])

    document = {
        "schema_version": "1",
        "artifact": "deployment-wiring",
        "subject": {
            "host": args.host,
            "jboss_home": str(args.jboss_home.resolve()),
            "instance": args.instance,
            "collection_mode": args.collection_mode,
        },
        "deployments": deployments,
    }
    payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.out == "-":
        sys.stdout.write(payload)
    else:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(payload, encoding="utf-8")
        print(
            f"deployment-wiring: {len(deployments)} deployments -> {out}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
