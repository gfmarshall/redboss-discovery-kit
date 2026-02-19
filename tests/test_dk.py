import unittest
import os
import json
import sys
import tempfile
import importlib.util
from pathlib import Path

# Load the extension-less 'dk' script as a module
def load_dk_module():
    project_root = Path(__file__).parent.parent
    dk_path = (project_root / "dk").resolve()
    if not dk_path.exists():
        raise FileNotFoundError(f"Could not find dk script at {dk_path}")
    
    spec = importlib.util.spec_from_file_location(
        "dk", str(dk_path),
        submodule_search_locations=[]
    )
    if spec is None or spec.loader is None:
        # Fallback: explicitly create a spec for extension-less files
        from importlib.machinery import ModuleSpec, SourceFileLoader
        loader = SourceFileLoader("dk", str(dk_path))
        spec = ModuleSpec("dk", loader, origin=str(dk_path))

    dk_module = importlib.util.module_from_spec(spec)
    dk_module.__file__ = str(dk_path)
    spec.loader.exec_module(dk_module)
    return dk_module

dk = load_dk_module()
DiscoveryEngine = dk.DiscoveryEngine
HashingUtil = dk.HashingUtil
SafetyGuard = dk.SafetyGuard
DKError = dk.DKError
validate_manifest = dk.validate_manifest

class TestDkCore(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="dk_test_")
        self.test_dir = Path(self._tmpdir)
        
        # Create a mock JBoss Home
        self.jboss_home = self.test_dir / "jboss-home"
        self.jboss_home.mkdir(exist_ok=True)
        (self.jboss_home / "jboss-modules.jar").touch()
        
        # Create a mock Instance
        self.instance_root = self.test_dir / "instances"
        self.instance_root.mkdir(exist_ok=True)
        self.app_instance = self.instance_root / "app1-instance"
        self.app_instance.mkdir(exist_ok=True)
        (self.app_instance / "configuration").mkdir(exist_ok=True)
        (self.app_instance / "deployments").mkdir(exist_ok=True)
        (self.app_instance / "configuration" / "standalone.xml").touch()

    def tearDown(self):
        import shutil
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)


class TestSafetyGuard(unittest.TestCase):
    def test_blocks_forbidden_extensions(self):
        manifest = {"safety": {"never_export_file_types": [".war", ".jar"]}}
        guard = SafetyGuard(manifest)
        with self.assertRaises(DKError):
            guard.assert_safe_to_write(Path("/tmp/app.war"))

    def test_allows_safe_extensions(self):
        manifest = {"safety": {"never_export_file_types": [".war", ".jar"]}}
        guard = SafetyGuard(manifest)
        guard.assert_safe_to_write(Path("/tmp/summary.json"))  # should not raise

    def test_is_safe_extension(self):
        guard = SafetyGuard({})  # uses defaults
        self.assertFalse(guard.is_safe_extension(Path("app.war")))
        self.assertFalse(guard.is_safe_extension(Path("lib.jar")))
        self.assertTrue(guard.is_safe_extension(Path("summary.json")))
        self.assertTrue(guard.is_safe_extension(Path("config.xml")))


class TestDKError(unittest.TestCase):
    def test_load_manifest_missing_file(self):
        with self.assertRaises(DKError):
            dk.load_manifest("/nonexistent/path/manifest.yml")

    def test_load_manifest_invalid_json(self):
        tmpfile = Path(tempfile.mktemp(suffix=".json"))
        tmpfile.write_text("{invalid json}")
        try:
            with self.assertRaises(DKError):
                dk.load_manifest(str(tmpfile))
        finally:
            tmpfile.unlink()


class TestManifestValidation(unittest.TestCase):
    """Tests for JSON Schema-based manifest validation."""

    def _valid_manifest(self):
        return {
            "manifest_version": 1,
            "jboss": {"home": "/opt/jboss"},
            "instances": {
                "discovery": {
                    "roots": ["/opt/instances"]
                }
            }
        }

    def test_valid_manifest_passes(self):
        errors = validate_manifest(self._valid_manifest())
        self.assertEqual(errors, [])

    def test_missing_manifest_version(self):
        m = self._valid_manifest()
        del m["manifest_version"]
        errors = validate_manifest(m)
        self.assertTrue(len(errors) > 0)

    def test_missing_jboss_home(self):
        m = self._valid_manifest()
        del m["jboss"]["home"]
        errors = validate_manifest(m)
        self.assertTrue(len(errors) > 0)

    def test_missing_discovery(self):
        m = self._valid_manifest()
        del m["instances"]["discovery"]
        errors = validate_manifest(m)
        self.assertTrue(len(errors) > 0)

    def test_empty_jboss_home_rejected(self):
        m = self._valid_manifest()
        m["jboss"]["home"] = ""
        errors = validate_manifest(m)
        self.assertTrue(len(errors) > 0)

    def test_invalid_manifest_version_value(self):
        m = self._valid_manifest()
        m["manifest_version"] = 999
        errors = validate_manifest(m)
        self.assertTrue(len(errors) > 0)

    def test_safety_bad_extension_format(self):
        m = self._valid_manifest()
        m["safety"] = {"never_export_file_types": ["war"]}  # missing leading dot
        errors = validate_manifest(m)
        self.assertTrue(len(errors) > 0)

    def test_full_manifest_with_all_sections(self):
        m = self._valid_manifest()
        m["sbom"] = {"formats": ["cyclonedx-json"], "scopes": ["platform", "apps"]}
        m["scan"] = {"platform_exclude": ["**/log/**"], "apps_include": ["deployments/**"]}
        m["safety"] = {"never_export_file_types": [".jar", ".war"]}
        errors = validate_manifest(m)
        self.assertEqual(errors, [])


class TestManifestVersionGate(unittest.TestCase):
    """Tests that load_manifest rejects unsupported manifest versions."""

    def test_rejects_unsupported_version(self):
        tmpfile = Path(tempfile.mktemp(suffix=".json"))
        data = {"manifest_version": 999, "jboss": {"home": "/x"}, "instances": {"discovery": {"roots": ["/"]}}}
        tmpfile.write_text(json.dumps(data))
        try:
            with self.assertRaises(DKError):
                dk.load_manifest(str(tmpfile))
        finally:
            tmpfile.unlink()

    def test_accepts_supported_version(self):
        tmpfile = Path(tempfile.mktemp(suffix=".json"))
        data = {"manifest_version": 1, "jboss": {"home": "/x"}, "instances": {"discovery": {"roots": ["/"]}}}
        tmpfile.write_text(json.dumps(data))
        try:
            result = dk.load_manifest(str(tmpfile))
            self.assertEqual(result["manifest_version"], 1)
        finally:
            tmpfile.unlink()


class TestDiscoveryEngine(TestDkCore):
    """Discovery and resolution tests that inherit the JBoss fixture from TestDkCore."""

    def test_jboss_home_resolution(self):
        manifest = {
            "jboss": {"home": str(self.jboss_home)},
            "instances": {"discovery": {}, "config": {}}
        }
        engine = DiscoveryEngine(manifest)
        self.assertEqual(engine.jboss_home, self.jboss_home.resolve())

    def test_instance_discovery(self):
        manifest = {
            "jboss": {"home": str(self.jboss_home)},
            "instances": {
                "discovery": {
                    "roots": [str(self.instance_root)],
                    "instance_globs": ["*-instance"],
                    "base_subdir_candidates": ["."],
                    "base_markers": ["configuration", "deployments"]
                },
                "config": {"candidates": ["standalone.xml"]}
            }
        }
        engine = DiscoveryEngine(manifest)
        instances = engine.discover_instances()
        self.assertEqual(len(instances), 1)
        self.assertEqual(instances[0]["name"], "app1-instance")

    def test_hashing(self):
        test_file = self.test_dir / "hash_test.txt"
        test_file.write_text("hello world")
        expected_hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        self.assertEqual(HashingUtil.hash_file(test_file), expected_hash)


if __name__ == "__main__":
    unittest.main()
