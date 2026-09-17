"""Tests for cmd_run — end-to-end with mocked Syft, manifest convert, and dry-run."""
import argparse
import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def _dk():
    from conftest import dk
    return dk


class TestCmdRun:
    def test_runtime_contract_fixture(self):
        contract_path = Path(__file__).parent / "contracts" / "dk-runtime-v1.json"
        contract = json.loads(contract_path.read_text())
        assert contract["contractVersion"] == "1.0.0"
        assert contract["exitCodes"] == {"complete": 0, "fatal": 1, "partial": 2}
        assert contract["outputs"]["archive"] == "<out>/<run-id>.tar.gz"
        assert contract["protectedRulesArgument"] == "--rules-dir"

    def test_cmd_run_creates_output_structure(self, valid_manifest, manifest_file, tmp_path, jboss_env):
        dk = _dk()
        out_dir = tmp_path / "evidence"

        args = argparse.Namespace(
            manifest=str(manifest_file),
            out=str(out_dir),
            archive=False,
        )

        # Mock syft so we don't need the binary
        fake_result = MagicMock(stdout='{"bomFormat":"CycloneDX"}')
        with patch("subprocess.run", return_value=fake_result):
            dk.cmd_run(args)

        # Verify run directory was created (YYMMDD-HHMM pattern)
        run_dirs = [d for d in out_dir.iterdir() if d.is_dir()]
        assert len(run_dirs) == 1

        run_out = run_dirs[0]
        # dk-pack.json must exist
        pack_path = run_out / "dk-pack.json"
        assert pack_path.exists()
        pack = json.loads(pack_path.read_text())
        assert pack["instance_count"] == 1
        assert "instance_errors" in pack
        assert isinstance(pack["instance_errors"], list)

        # Instance directory
        inst_out = run_out / "app1-instance"
        assert inst_out.is_dir()
        assert (inst_out / "summary.json").exists()
        assert (inst_out / "fingerprints.json").exists()

    def test_cmd_run_records_instance_errors(self, valid_manifest, manifest_file, tmp_path, jboss_env):
        dk = _dk()
        out_dir = tmp_path / "evidence"

        args = argparse.Namespace(
            manifest=str(manifest_file),
            out=str(out_dir),
            archive=False,
        )

        # Make process_instance blow up
        with patch.object(dk, "process_instance", side_effect=RuntimeError("boom")):
            exit_code = dk.cmd_run(args)

        assert exit_code == 2
        run_dirs = [d for d in out_dir.iterdir() if d.is_dir()]
        run_out = run_dirs[0]
        pack = json.loads((run_out / "dk-pack.json").read_text())
        assert len(pack["instance_errors"]) == 1
        assert "boom" in pack["instance_errors"][0]["error"]

    def test_cmd_run_records_sbom_failure_as_partial(self, valid_manifest, manifest_file, tmp_path, jboss_env):
        dk = _dk()
        out_dir = tmp_path / "evidence"
        args = argparse.Namespace(
            manifest=str(manifest_file),
            out=str(out_dir),
            archive=True,
        )
        version_result = MagicMock(stdout="Version: 1.42.0\n")
        failure = subprocess.CalledProcessError(1, ["syft"], stderr="failed")

        with patch("subprocess.run", side_effect=[version_result, failure, failure]):
            exit_code = dk.cmd_run(args)

        assert exit_code == 2
        run_dir = next(path for path in out_dir.iterdir() if path.is_dir())
        pack = json.loads((run_dir / "dk-pack.json").read_text())
        assert "SBOM generation failed" in pack["instance_errors"][0]["error"]
        assert next(out_dir.glob("*.tar.gz")).is_file()

    def test_cmd_run_no_instances_raises(self, tmp_path):
        dk = _dk()
        # Manifest pointing to empty roots
        m = {
            "manifest_version": 1,
            "jboss": {"home": str(tmp_path / "nope")},
            "instances": {
                "discovery": {"roots": [str(tmp_path / "empty")]},
            },
        }
        mf = tmp_path / "m.json"
        mf.write_text(json.dumps(m))
        (tmp_path / "empty").mkdir()

        args = argparse.Namespace(
            manifest=str(mf), out=str(tmp_path / "out"),
            archive=False,
        )
        with pytest.raises(dk.DKError, match="No instances discovered"):
            dk.cmd_run(args)

    def test_cmd_run_archive_creates_tarball(self, valid_manifest, manifest_file, tmp_path, jboss_env):
        dk = _dk()
        out_dir = tmp_path / "evidence"

        args = argparse.Namespace(
            manifest=str(manifest_file),
            out=str(out_dir),
            archive=True,
        )

        fake_result = MagicMock(stdout='{}')
        with patch("subprocess.run", return_value=fake_result):
            dk.cmd_run(args)

        tarballs = list(out_dir.glob("*.tar.gz"))
        assert len(tarballs) == 1

    def test_cmd_run_uses_explicit_run_id_for_deterministic_paths(self, valid_manifest, manifest_file, tmp_path, jboss_env):
        dk = _dk()
        out_dir = tmp_path / "evidence"
        args = argparse.Namespace(
            manifest=str(manifest_file),
            out=str(out_dir),
            run_id="ado-12345-dc1dev356",
            archive=True,
        )

        fake_result = MagicMock(stdout='{}')
        with patch("subprocess.run", return_value=fake_result):
            exit_code = dk.cmd_run(args)

        assert exit_code == 0
        assert (out_dir / "ado-12345-dc1dev356" / "dk-pack.json").exists()
        assert (out_dir / "ado-12345-dc1dev356.tar.gz").exists()
        pack = json.loads((out_dir / "ado-12345-dc1dev356" / "dk-pack.json").read_text())
        assert pack["run_id"] == "ado-12345-dc1dev356"

    def test_cmd_run_rejects_invalid_run_id(self, manifest_file, tmp_path):
        dk = _dk()
        args = argparse.Namespace(
            manifest=str(manifest_file),
            out=str(tmp_path / "evidence"),
            run_id="../escape",
            archive=False,
        )

        with pytest.raises(dk.DKError, match="Run ID must match"):
            dk.cmd_run(args)

    def test_cmd_run_rejects_existing_run_output(self, valid_manifest, manifest_file, tmp_path, jboss_env):
        dk = _dk()
        out_dir = tmp_path / "evidence"
        (out_dir / "duplicate").mkdir(parents=True)
        args = argparse.Namespace(
            manifest=str(manifest_file),
            out=str(out_dir),
            run_id="duplicate",
            archive=False,
        )

        with pytest.raises(dk.DKError, match="Run output already exists"):
            dk.cmd_run(args)


class TestCmdDryRun:
    def test_dry_run_no_side_effects(self, valid_manifest, manifest_file, tmp_path, jboss_env):
        dk = _dk()
        args = argparse.Namespace(manifest=str(manifest_file))
        # Should not raise and should not create any output dirs
        dk.cmd_dry_run(args)
        evidence = tmp_path / "generated-evidence"
        assert not evidence.exists()


class TestCmdManifestConvert:
    def test_yaml_to_json(self, tmp_path):
        dk = _dk()
        yaml_file = tmp_path / "test.yml"
        yaml_file.write_text("manifest_version: 1\njboss:\n  home: /opt/jboss\n")

        args = argparse.Namespace(in_file=str(yaml_file), out_file=None)
        dk.cmd_manifest_convert(args)

        json_file = yaml_file.with_suffix(".json")
        assert json_file.exists()
        data = json.loads(json_file.read_text())
        assert data["manifest_version"] == 1

    def test_json_to_yaml(self, tmp_path):
        dk = _dk()
        json_file = tmp_path / "test.json"
        json_file.write_text(json.dumps({"manifest_version": 1, "jboss": {"home": "/x"}}))

        args = argparse.Namespace(in_file=str(json_file), out_file=None)
        dk.cmd_manifest_convert(args)

        yml_file = json_file.with_suffix(".yml")
        assert yml_file.exists()

    def test_explicit_output_path(self, tmp_path):
        dk = _dk()
        src = tmp_path / "in.json"
        dst = tmp_path / "custom_out.yml"
        src.write_text(json.dumps({"key": "val"}))

        args = argparse.Namespace(in_file=str(src), out_file=str(dst))
        dk.cmd_manifest_convert(args)
        assert dst.exists()

    def test_missing_input_raises(self, tmp_path):
        dk = _dk()
        args = argparse.Namespace(in_file=str(tmp_path / "nope.json"), out_file=None)
        with pytest.raises(dk.DKError, match="Input manifest not found"):
            dk.cmd_manifest_convert(args)
