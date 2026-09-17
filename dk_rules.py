from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import jsonschema
import yaml
from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException


class RulesError(Exception):
    pass


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _namespace(tag: str) -> str:
    return tag[1:].split("}", 1)[0] if tag.startswith("{") else ""


def _safe_child(root: Path, *parts: str) -> Path:
    candidate = root.joinpath(*parts).resolve()
    if candidate != root and root not in candidate.parents:
        raise RulesError("Protected rules path escapes the rules directory")
    return candidate


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RulesError("Protected rules YAML could not be loaded") from exc
    if not isinstance(value, dict):
        raise RulesError("Protected rules YAML must contain an object")
    return value


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RulesError("Protected rules JSON could not be loaded") from exc
    if not isinstance(value, dict):
        raise RulesError("Protected rules JSON must contain an object")
    return value


def _validate(value: dict[str, Any], schema_path: Path, label: str) -> None:
    schema = _load_json(schema_path)
    errors = list(jsonschema.Draft7Validator(schema).iter_errors(value))
    if errors:
        raise RulesError(f"{label} does not satisfy its schema")


class ProtectedRulesAdapter:
    _selector_token = re.compile(
        r"^(?P<name>[A-Za-z][A-Za-z0-9-]*)(?:\[contains\(@xmlns,\s*['\"](?P<namespace>[^'\"]+)['\"]\)\])?$"
    )
    _field = re.compile(r'^([A-Za-z][A-Za-z0-9_]*)\s*:\s*"([^"]+)"\s*,?$')
    _count = re.compile(r"^count\(//([A-Za-z][A-Za-z0-9-]*)\)\s+as\s+([A-Za-z][A-Za-z0-9_]*)$")
    _sensitive_field = re.compile(r"password|secret|token|credential|access_key", re.IGNORECASE)

    def __init__(self, rules_dir: Path, manifest: dict[str, Any]):
        self.rules_dir = rules_dir.resolve()
        if not self.rules_dir.is_dir():
            raise RulesError("Protected rules directory does not exist")

        config = manifest.get("dkpp")
        if not isinstance(config, dict) or config.get("enabled") is not True:
            raise RulesError("Manifest must explicitly enable DK++")
        if config.get("extract", {}).get("mode") != "facts-only":
            raise RulesError("DK++ extraction mode must be facts-only")
        if config.get("extract", {}).get("redaction_policy") != "strict":
            raise RulesError("DK++ redaction policy must be strict")

        self.pack = _load_json(_safe_child(self.rules_dir, "pack.json"))
        _validate(
            self.pack,
            _safe_child(self.rules_dir, "schemas", "pack.schema.json"),
            "DK++ pack",
        )
        if self.pack.get("id") != "redboss-dk-plus":
            raise RulesError("Protected rules pack identity is invalid")

        profile_name = config.get("profile")
        if not isinstance(profile_name, str) or profile_name not in self.pack.get("profiles", []):
            raise RulesError("Requested DK++ profile is not declared by the pack")
        self.profile = _load_yaml(_safe_child(self.rules_dir, "profiles", f"{profile_name}.yml"))
        _validate(
            self.profile,
            _safe_child(self.rules_dir, "schemas", "profile.schema.json"),
            "DK++ profile",
        )
        if self.profile.get("profile_name") != profile_name:
            raise RulesError("DK++ profile identity does not match its filename")

        self.redaction = self._load_redaction_policy("strict", set())
        regex_config = self.redaction.get("regex_scrub", {})
        if regex_config.get("enabled") is not True:
            raise RulesError("Strict DK++ regex redaction must be enabled")
        try:
            self.redaction_patterns = [
                re.compile(pattern, re.IGNORECASE) for pattern in regex_config.get("patterns", [])
            ]
        except re.error as exc:
            raise RulesError("DK++ redaction pattern is invalid") from exc
        if not self.redaction_patterns:
            raise RulesError("Strict DK++ redaction has no patterns")

        self.groups = self._load_groups()

    def _load_redaction_policy(self, name: str, seen: set[str]) -> dict[str, Any]:
        if name in seen:
            raise RulesError("DK++ redaction inheritance contains a cycle")
        seen.add(name)
        value = _load_yaml(_safe_child(self.rules_dir, "redaction", f"{name}.yml"))
        policy = value.get("redaction_policy")
        if not isinstance(policy, dict) or policy.get("name") != name:
            raise RulesError("DK++ redaction policy identity is invalid")
        inherited = policy.get("inherits")
        if inherited:
            parent = self._load_redaction_policy(inherited, seen)
            policy = {
                **parent,
                **policy,
                "xpaths": [*parent.get("xpaths", []), *policy.get("xpaths", [])],
                "regex_scrub": {
                    **parent.get("regex_scrub", {}),
                    **policy.get("regex_scrub", {}),
                },
            }
        return policy

    def _load_groups(self) -> dict[str, list[str]]:
        groups: dict[str, list[str]] = {}
        for entry in self.profile.get("extract_groups", []):
            group = entry["group"]
            if group in groups:
                raise RulesError("DK++ profile contains a duplicate extraction group")
            rules: list[str] = []
            for relative_path in entry["xpath_files"]:
                path = _safe_child(self.rules_dir, "xpaths", relative_path)
                try:
                    rules.append(path.read_text(encoding="utf-8"))
                except OSError as exc:
                    raise RulesError("DK++ extraction rules could not be loaded") from exc
            groups[group] = rules
        if not groups:
            raise RulesError("DK++ profile contains no extraction groups")
        return groups

    def metadata(self) -> dict[str, str]:
        return {
            "pack_id": self.pack["id"],
            "ruleset_version": self.pack["ruleset_version"],
            "profile": self.profile["profile_name"],
            "redaction_policy": self.redaction["name"],
        }

    def extract(self, config_path: Path) -> dict[str, Any]:
        try:
            if config_path.stat().st_size > 64 * 1024 * 1024:
                raise RulesError("JBoss configuration exceeds the extraction size limit")
            root = ElementTree.parse(config_path).getroot()
        except RulesError:
            raise
        except (OSError, ElementTree.ParseError, DefusedXmlException) as exc:
            raise RulesError("JBoss configuration could not be parsed") from exc

        extracted: dict[str, Any] = {
            "schema_version": 1,
            **self.metadata(),
            "groups": {},
        }
        for group, rule_documents in self.groups.items():
            items: list[dict[str, Any]] = []
            counts: dict[str, int] = {}
            for document in rule_documents:
                document_items, document_counts = self._evaluate_document(root, document)
                items.extend(document_items)
                for name, value in document_counts.items():
                    if name in counts:
                        raise RulesError("DK++ extraction rules contain a duplicate count")
                    counts[name] = value
            extracted["groups"][group] = {"items": items, "counts": counts}
        return extracted

    def _evaluate_document(
        self, root: ElementTree.Element, document: str
    ) -> tuple[list[dict[str, Any]], dict[str, int]]:
        content = "\n".join(
            line for line in document.splitlines() if line.strip() and not line.lstrip().startswith("#")
        )
        blocks = re.findall(r"(?ms)(//[^\n{]+)\s*\{(.*?)\}", content)
        content_without_blocks = re.sub(r"(?ms)//[^\n{]+\s*\{.*?\}", "", content)
        items: list[dict[str, Any]] = []
        for selector, body in blocks:
            fields = self._parse_fields(body)
            for element in self._select(root, selector.strip()):
                item: dict[str, Any] = {"kind": _local_name(element.tag)}
                for name, expression in fields:
                    item[name] = self._scrub(self._field_value(element, expression))
                items.append(item)

        counts: dict[str, int] = {}
        for line in content_without_blocks.splitlines():
            if not line.strip():
                continue
            match = self._count.fullmatch(line.strip())
            if not match:
                raise RulesError("DK++ extraction rule syntax is unsupported")
            tag, alias = match.groups()
            counts[alias] = sum(1 for element in root.iter() if _local_name(element.tag) == tag)
        return items, counts

    def _parse_fields(self, body: str) -> list[tuple[str, str]]:
        fields: list[tuple[str, str]] = []
        for line in body.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            match = self._field.fullmatch(stripped)
            if not match:
                raise RulesError("DK++ fact field syntax is unsupported")
            name, expression = match.groups()
            if self._sensitive_field.search(name):
                raise RulesError("DK++ fact field name is prohibited")
            fields.append((name, expression))
        if not fields:
            raise RulesError("DK++ extraction block contains no fields")
        return fields

    def _select(self, root: ElementTree.Element, selector: str) -> list[ElementTree.Element]:
        if not selector.startswith("//"):
            raise RulesError("DK++ selectors must start with descendant scope")
        pieces = re.split(r"(//|/)", selector[2:])
        segments: list[tuple[str, str]] = []
        axis = "descendant"
        for piece in pieces:
            if piece in {"/", "//"}:
                axis = "descendant" if piece == "//" else "child"
            elif piece:
                segments.append((axis, piece.strip()))
        current = [root]
        for index, (segment_axis, token) in enumerate(segments):
            match = self._selector_token.fullmatch(token)
            if not match:
                raise RulesError("DK++ selector syntax is unsupported")
            candidates: Iterable[ElementTree.Element]
            if index == 0 or segment_axis == "descendant":
                candidates = (item for parent in current for item in parent.iter())
            else:
                candidates = (item for parent in current for item in list(parent))
            name = match.group("name")
            namespace = match.group("namespace")
            current = [
                item
                for item in candidates
                if _local_name(item.tag) == name and (not namespace or namespace in _namespace(item.tag))
            ]
        return current

    def _field_value(self, element: ElementTree.Element, expression: str) -> Any:
        if expression.startswith("@"):
            return element.attrib.get(expression[1:])
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9-]*)(?:/(text\(\)|@[A-Za-z][A-Za-z0-9-]*))", expression)
        if not match:
            raise RulesError("DK++ fact value expression is unsupported")
        child_name, accessor = match.groups()
        children = [child for child in list(element) if _local_name(child.tag) == child_name]
        values = [
            (child.text or "").strip() if accessor == "text()" else child.attrib.get(accessor[1:]) for child in children
        ]
        values = [value for value in values if value is not None]
        if not values:
            return None
        return values[0] if len(values) == 1 else values

    def _scrub(self, value: Any) -> Any:
        if isinstance(value, list):
            return [self._scrub(item) for item in value]
        if not isinstance(value, str):
            return value
        scrubbed = value
        for pattern in self.redaction_patterns:
            scrubbed = pattern.sub("[REDACTED]", scrubbed)
        return scrubbed
