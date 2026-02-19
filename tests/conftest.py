"""Shared pytest fixtures for the Red Boss Discovery Kit test suite."""
import json
import shutil
import tempfile
import importlib.util
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Module loader – import the extension-less `dk` script as a Python module
# ---------------------------------------------------------------------------
def _load_dk_module():
    project_root = Path(__file__).parent.parent
    dk_path = (project_root / "dk").resolve()
    if not dk_path.exists():
        raise FileNotFoundError(f"Could not find dk script at {dk_path}")

    spec = importlib.util.spec_from_file_location(
        "dk", str(dk_path), submodule_search_locations=[]
    )
    if spec is None or spec.loader is None:
        from importlib.machinery import ModuleSpec, SourceFileLoader
        loader = SourceFileLoader("dk", str(dk_path))
        spec = ModuleSpec("dk", loader, origin=str(dk_path))

    dk_module = importlib.util.module_from_spec(spec)
    dk_module.__file__ = str(dk_path)
    spec.loader.exec_module(dk_module)
    return dk_module


dk = _load_dk_module()


@pytest.fixture
def dk_mod():
    """Provides the dk module for tests that need direct access."""
    return dk


# ---------------------------------------------------------------------------
# Temporary JBoss environment fixture
# ---------------------------------------------------------------------------
@pytest.fixture
def jboss_env(tmp_path):
    """Creates a realistic mock JBoss file-system tree and returns paths."""
    jboss_home = tmp_path / "jboss-home"
    jboss_home.mkdir()
    (jboss_home / "jboss-modules.jar").touch()

    instance_root = tmp_path / "instances"
    instance_root.mkdir()

    app_instance = instance_root / "app1-instance"
    app_instance.mkdir()
    (app_instance / "configuration").mkdir()
    (app_instance / "deployments").mkdir()
    (app_instance / "configuration" / "standalone.xml").write_text("<server/>")

    return {
        "tmp_path": tmp_path,
        "jboss_home": jboss_home,
        "instance_root": instance_root,
        "app_instance": app_instance,
    }


@pytest.fixture
def valid_manifest(jboss_env):
    """Returns a minimal valid manifest dict wired to the jboss_env paths."""
    return {
        "manifest_version": 1,
        "jboss": {"home": str(jboss_env["jboss_home"])},
        "instances": {
            "discovery": {
                "roots": [str(jboss_env["instance_root"])],
                "instance_globs": ["*-instance"],
                "base_subdir_candidates": ["."],
                "base_markers": ["configuration", "deployments"],
            },
            "config": {"candidates": ["standalone.xml"]},
        },
        "safety": {
            "never_export_file_types": [".jar", ".war", ".ear", ".zip", ".tar", ".tgz", ".gz"]
        },
    }


@pytest.fixture
def manifest_file(valid_manifest, tmp_path):
    """Writes the valid_manifest to a JSON file and returns its Path."""
    p = tmp_path / "dk-manifest.json"
    p.write_text(json.dumps(valid_manifest, indent=2))
    return p
