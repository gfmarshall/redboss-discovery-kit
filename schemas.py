# Red Boss Discovery Kit — JSON Schemas
# Defines contracts for manifest input and all output artifacts.
# Used by dk for validation at runtime and as machine-readable documentation.

SUPPORTED_MANIFEST_VERSIONS = [1]

MANIFEST_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "DK Core Manifest",
    "description": "Schema for the Red Boss Discovery Kit manifest file.",
    "type": "object",
    "required": ["manifest_version", "jboss", "instances"],
    "additionalProperties": True,
    "properties": {
        "manifest_version": {
            "type": "integer",
            "enum": SUPPORTED_MANIFEST_VERSIONS,
            "description": "Schema version of this manifest."
        },
        "jboss": {
            "type": "object",
            "required": ["home"],
            "properties": {
                "home": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Path or glob pattern to the JBoss EAP installation."
                },
                "mode": {
                    "type": "string",
                    "enum": ["standalone", "domain"],
                    "default": "standalone"
                }
            },
            "additionalProperties": False
        },
        "instances": {
            "type": "object",
            "required": ["discovery"],
            "properties": {
                "discovery": {
                    "type": "object",
                    "required": ["roots"],
                    "properties": {
                        "roots": {
                            "type": "array",
                            "items": {"type": "string", "minLength": 1},
                            "minItems": 1,
                            "description": "Directories to search for JBoss instances."
                        },
                        "instance_globs": {
                            "type": "array",
                            "items": {"type": "string"},
                            "default": ["*"]
                        },
                        "base_subdir_candidates": {
                            "type": "array",
                            "items": {"type": "string"},
                            "default": [".", "standalone"]
                        },
                        "base_markers": {
                            "type": "array",
                            "items": {"type": "string"},
                            "default": ["configuration", "deployments"]
                        }
                    },
                    "additionalProperties": False
                },
                "config": {
                    "type": "object",
                    "properties": {
                        "candidates": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "selected": {
                            "type": "string"
                        }
                    },
                    "additionalProperties": False
                }
            },
            "additionalProperties": False
        },
        "sbom": {
            "type": "object",
            "properties": {
                "formats": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "scopes": {
                    "type": "array",
                    "items": {"type": "string"}
                }
            },
            "additionalProperties": False
        },
        "scan": {
            "type": "object",
            "properties": {
                "platform_exclude": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "apps_include": {
                    "type": "array",
                    "items": {"type": "string"}
                }
            },
            "additionalProperties": False
        },
        "safety": {
            "type": "object",
            "properties": {
                "never_export_file_types": {
                    "type": "array",
                    "items": {"type": "string", "pattern": "^\\."},
                    "description": "File extensions that must never be exported."
                }
            },
            "additionalProperties": False
        },
        "dkpp": {
            "type": "object",
            "required": ["enabled", "profile", "extract"],
            "properties": {
                "enabled": {"const": True},
                "profile": {"type": "string", "minLength": 1},
                "extract": {
                    "type": "object",
                    "required": ["mode", "redaction_policy"],
                    "properties": {
                        "mode": {"const": "facts-only"},
                        "redaction_policy": {"const": "strict"}
                    },
                    "additionalProperties": False
                },
                "drift_payload": {
                    "type": "object",
                    "properties": {"enabled": {"type": "boolean"}},
                    "additionalProperties": False
                }
            },
            "additionalProperties": False
        }
    }
}

SUMMARY_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "DK Instance Summary",
    "description": "Per-instance metadata produced by a DK run.",
    "type": "object",
    "required": ["instance_name", "instance_base", "jboss_home", "mode", "timestamp"],
    "properties": {
        "instance_name": {"type": "string"},
        "instance_base": {"type": "string"},
        "selected_config": {"type": ["string", "null"]},
        "jboss_home": {"type": "string"},
        "mode": {"type": "string", "enum": ["standalone", "domain"]},
        "timestamp": {"type": "string", "format": "date-time"}
    },
    "additionalProperties": False
}

FINGERPRINT_ITEM_SCHEMA = {
    "type": "object",
    "required": ["path", "size_bytes", "mtime", "sha256"],
    "properties": {
        "path": {"type": "string"},
        "size_bytes": {"type": "integer", "minimum": 0},
        "mtime": {"type": "string", "format": "date-time"},
        "sha256": {"type": ["string", "null"], "pattern": "^[a-f0-9]{64}$"}
    },
    "additionalProperties": False
}

FINGERPRINTS_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "DK Fingerprints",
    "description": "Collection of SHA-256 fingerprints for deployments and configs.",
    "type": "array",
    "items": FINGERPRINT_ITEM_SCHEMA
}

DKPP_FACT_VALUE_SCHEMA = {
    "oneOf": [
        {"type": "string"},
        {"type": "null"},
        {"type": "array", "items": {"type": "string"}}
    ]
}

DKPP_FACTS_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "DK++ Facts-Only Extraction",
    "type": "object",
    "required": [
        "schema_version", "pack_id", "ruleset_version", "profile",
        "redaction_policy", "groups"
    ],
    "properties": {
        "schema_version": {"const": 1},
        "pack_id": {"const": "redboss-dk-plus"},
        "ruleset_version": {"type": "string"},
        "profile": {"type": "string"},
        "redaction_policy": {"const": "strict"},
        "groups": {
            "type": "object",
            "minProperties": 1,
            "additionalProperties": {
                "type": "object",
                "required": ["items", "counts"],
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["kind"],
                            "properties": {"kind": {"type": "string"}},
                            "patternProperties": {
                                "^[A-Za-z][A-Za-z0-9_]*$": DKPP_FACT_VALUE_SCHEMA
                            },
                            "additionalProperties": False
                        }
                    },
                    "counts": {
                        "type": "object",
                        "patternProperties": {
                            "^[A-Za-z][A-Za-z0-9_]*$": {
                                "type": "integer", "minimum": 0
                            }
                        },
                        "additionalProperties": False
                    }
                },
                "additionalProperties": False
            }
        }
    },
    "additionalProperties": False
}

DK_PACK_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "DK Pack",
    "description": "Global run metadata and safety attestation.",
    "type": "object",
    "required": [
        "run_id", "tool_version", "syft_version", "dkpp", "manifest_hash",
        "instance_count", "timestamp", "attestation", "instance_errors"
    ],
    "properties": {
        "run_id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"},
        "tool_version": {"type": "string"},
        "syft_version": {"type": "string"},
        "dkpp": {
            "oneOf": [
                {"type": "null"},
                {
                    "type": "object",
                    "required": ["pack_id", "ruleset_version", "profile", "redaction_policy"],
                    "properties": {
                        "pack_id": {"const": "redboss-dk-plus"},
                        "ruleset_version": {"type": "string"},
                        "profile": {"type": "string"},
                        "redaction_policy": {"const": "strict"}
                    },
                    "additionalProperties": False
                }
            ]
        },
        "manifest_hash": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
        "instance_count": {"type": "integer", "minimum": 0},
        "timestamp": {"type": "string", "format": "date-time"},
        "attestation": {
            "type": "object",
            "required": ["no_binaries_exported", "config_files_hashed_only"],
            "properties": {
                "no_binaries_exported": {"type": "boolean"},
                "config_files_hashed_only": {"type": "boolean"}
            },
            "additionalProperties": False
        },
        "instance_errors": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["instance", "error"],
                "properties": {
                    "instance": {"type": "string"},
                    "error": {"type": "string"}
                },
                "additionalProperties": False
            },
            "description": "Errors encountered during per-instance processing."
        }
    },
    "additionalProperties": False
}
