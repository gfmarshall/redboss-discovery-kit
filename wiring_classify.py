#!/usr/bin/env python3
"""ci/lib/wiring_classify.py

S42-05: shared field-classification engine for the wiring corpus
(ADR-0019). Three sensitivity classes:

    structural     -> emitted in the clear
    locator        -> emitted as eng:<hmac-sha256> keyed hash
    secret-shaped  -> emitted as REDACTED (never any form of the value)

Locator hashing is keyed, engagement-scoped, and domain-separated:
    eng:HMAC-SHA256(key, domain | value)
so identical values compare equal within an engagement, drift is
detectable, raw values are never disclosed, and hashes cannot be
correlated across engagements or brute-forced offline (the engagement
key is the entropy source, not the value).

Key sources, in order:
    1. --locator-key-file PATH (file contents, trailing newline stripped)
    2. $RB_WIRING_LOCATOR_KEY environment variable
    3. --insecure-unkeyed-locators flag: fixed domain-only key. The
       hashes stay deterministic (equality/drift still work) but are
       NOT engagement-scoped and are brute-forceable — dev/test only,
       and the wiring-manifest attestation declares locator_keying=
       "unkeyed" so the posture is never silently weak.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from pathlib import Path

UNKEYED_DOMAIN_KEY = b"redboss-wiring-unkeyed-locator-key"

SECRET_NAME_RE = re.compile(
    r"(?i)(pass(word|wd)?|secret|token|credential|private[-_.]?key|"
    r"key[-_.]?(store|pass)|bind[-_.]?credential|salt|pin\b)"
)
VAULT_EXPR_RE = re.compile(r"\$\{VAULT::[^}]*\}")
LOCATOR_VALUE_RE = re.compile(
    r"(?i)^("
    r"[a-z][a-z0-9+.-]*://"                       # scheme:// URLs
    r"|jdbc:[a-z]+:"                              # JDBC URLs
    r"|\d{1,3}(\.\d{1,3}){3}"                    # IPv4
    r"|[0-9a-f]*:[0-9a-f:]+:[0-9a-f.]+"          # IPv6-ish
    r"|[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)+"  # dotted hostname
    r"|/[a-z0-9._/-]+"                           # absolute path
    r")"
)


class LocatorKey:
    """Keyed-hash engine; tracks whether the key is engagement-scoped."""

    def __init__(self, key: bytes | None):
        self._key = key if key else UNKEYED_DOMAIN_KEY
        self.keying = "engagement-scoped" if key else "unkeyed"

    @classmethod
    def resolve(cls, key_file: str | None, insecure_ok: bool) -> "LocatorKey":
        if key_file:
            data = Path(key_file).read_bytes().rstrip(b"\n")
            if not data:
                raise SystemExit("locator key file is empty")
            return cls(data)
        env = os.environ.get("RB_WIRING_LOCATOR_KEY")
        if env:
            return cls(env.encode("utf-8"))
        if insecure_ok:
            return cls(None)
        raise SystemExit(
            "no locator key: set RB_WIRING_LOCATOR_KEY, pass "
            "--locator-key-file, or use --insecure-unkeyed-locators "
            "(dev/test only)"
        )

    def hash(self, domain: str, value: str) -> str:
        digest = hmac.new(
            self._key, f"{domain}|{value}".encode("utf-8"), hashlib.sha256
        )
        return f"eng:{digest.hexdigest()}"


def classify_property(name: str, value: str | None) -> tuple[str, str]:
    """Return (class, emitted_value) for one system property."""
    value = value or ""
    if SECRET_NAME_RE.search(name) or VAULT_EXPR_RE.search(value):
        return "secret-shaped", "REDACTED"
    return "unclassified", value


def is_locator_shaped(value: str) -> bool:
    return bool(LOCATOR_VALUE_RE.match(value))
