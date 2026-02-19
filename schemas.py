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

DK_PACK_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "DK Pack",
    "description": "Global run metadata and safety attestation.",
    "type": "object",
    "required": [
        "tool_version", "syft_version", "manifest_hash",
        "instance_count", "timestamp", "attestation", "instance_errors"
    ],
    "properties": {
        "tool_version": {"type": "string"},
        "syft_version": {"type": "string"},
        "manifest_hash": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
        "instance_count": {"type": "integer", "minimum": 0},
        "timestamp": {"type": "string", "format": "date-time"},
        "attestation": {
            "type": "object",
            "required": ["no_binaries_exported", "config_files_hashed_only"],
            "properties": {
                "no_binaries_exported": {"type": "boolean"},
                "config_files_hashed_only": {"type": "boolean"},
                "rules_dir_loaded": {"type": "boolean"}
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
