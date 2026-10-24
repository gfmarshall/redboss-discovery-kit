#!/usr/bin/env python3
"""ci/lib/wiring_scan.py

S42-08: pre-publish secrets-scan gate for the derived wiring corpus
(ADR-0019). The sensitivity model is enforced at derivation time — this
scan is the BACKSTOP that proves nothing secret-shaped survived: a
misclassified structural field, a password-looking string inside an
allowlisted attribute, a vault expression that escaped the classifier.

Deliberately precise, not heuristic: the corpus legitimately contains
thousands of sha256 digests and eng:<hmac> locator hashes, so entropy
scanning would false-positive constantly. The gate hunts *shapes that
can only be secret material*:

    - PEM markers (BEGIN ... PRIVATE KEY / CERTIFICATE)
    - secret-named key=value / "key": value literals in raw text
    - ${VAULT::...} expressions (credential locators)
    - JDBC URLs carrying credentials (jdbc:*...password/user=)
    - well-known token prefixes (AKIA, ghp_, eyJ JWT header, xox[baprs]-)
    - cleartext host:port@userinfo inside URL-shaped strings

eng:<64-hex> locator hashes and plain 64-hex sha256 digests are never
flagged — they are the corpus's own sanctioned encodings.

Usage (also wired into wiring_emit.py post-emission):
    wiring_scan.py PATH [PATH ...]     # files or dirs (recursive *.json)

Exit 0 = clean. Exit 1 = hits found (locations reported as path:line
only — the matched secret is NEVER echoed).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

PATTERNS: list[tuple[str, re.Pattern]] = [
    ("pem-material", re.compile(r"BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE)")),
    (
        # Catches config-style `password=x` AND JSON `"password":"x"` —
        # a quote between name and separator must not evade the gate.
        "named-secret-literal",
        re.compile(
            r"(?i)(?<![\w.])(pass(word|wd)?|secret|credential|"
            r"api[-_]?key|access[-_]?key|auth[-_]?token)[\"']?\s*[:=]"
            r"\s*[\"']?\S"
        ),
    ),
    ("vault-expression", re.compile(r"\$\{VAULT::[^}]*\}")),
    (
        "jdbc-credential",
        re.compile(r"(?i)jdbc:[a-z0-9]+:[^\"'\s]*\b(password|pwd|user)\s*="),
    ),
    ("aws-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("jwt-token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.")),
    ("slack-token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    (
        "url-userinfo",
        re.compile(r"[a-z][a-z0-9+.-]*://[^/\s\"']+:[^@/\s\"']+@"),
    ),
]

# Sanctioned encodings inside the corpus — never flagged.
SANCTIONED = re.compile(r"^eng:[0-9a-f]{64}$|^[0-9a-f]{64}$|^REDACTED$")

# Corpus records carry {name, class, value} (server-roots properties /
# subsystem attributes) and {name, before, after} (drift registers). A
# secret-shaped NAME beside a non-sanctioned VALUE is a misclassified
# or mis-redacted leak regardless of which JSON line each member sits
# on — the text pass cannot see that shape, so parsed-JSON records get
# their own check.
SECRET_NAME = re.compile(
    r"(?i)(pass(word|wd)?|secret|credential|api[-_]?key|"
    r"access[-_]?key|auth[-_]?token)"
)
RECORD_VALUE_KEYS = ("value", "before", "after")


def _json_record_hits(path: Path) -> list[str]:
    """Field names of secret-named records holding non-sanctioned values."""
    try:
        import json

        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    hits: list[str] = []

    def walk(node) -> None:
        if isinstance(node, dict):
            name = node.get("name")
            if isinstance(name, str) and SECRET_NAME.search(name):
                for k in RECORD_VALUE_KEYS:
                    v = node.get(k)
                    if isinstance(v, str) and not SANCTIONED.match(v):
                        hits.append("json-secret-record")
                        break
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(doc)
    return hits


def iter_files(paths: list[str]):
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            yield from sorted(p.rglob("*.json"))
        elif p.is_file():
            yield p


def scan_file(path: Path) -> list[tuple[int, str]]:
    """Return [(lineno, pattern-name)] — values are never returned."""
    hits = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        print(f"scan: cannot read {path}: {exc}", file=sys.stderr)
        return hits
    for lineno, line in enumerate(lines, 1):
        for name, pattern in PATTERNS:
            for match in pattern.finditer(line):
                if SANCTIONED.match(match.group(0)):
                    continue
                hits.append((lineno, name))
                break
    hits.extend((0, name) for name in _json_record_hits(path))
    return hits


def scan(paths: list[str]) -> dict[str, list[tuple[int, str]]]:
    return {
        str(p): hits
        for p in iter_files(paths)
        if (hits := scan_file(p))
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("paths", nargs="+")
    args = ap.parse_args(argv)
    results = scan(args.paths)
    for path, hits in results.items():
        shown = ", ".join(f"L{ln}:{name}" for ln, name in hits[:5])
        more = f" (+{len(hits) - 5} more)" if len(hits) > 5 else ""
        print(f"HIT  {path}: {shown}{more}", file=sys.stderr)
    if results:
        return 1
    print("secrets-scan: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
