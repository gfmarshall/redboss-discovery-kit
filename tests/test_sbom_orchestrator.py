"""Tests for SbomOrchestrator — subprocess timeout, retry, and SBOM generation."""
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


def _get_orch_class():
    from conftest import dk
    return dk.SbomOrchestrator


class TestSbomOrchestratorSuccess:
    def test_generate_sbom_writes_output(self, tmp_path):
        SbomOrchestrator = _get_orch_class()
        out_file = tmp_path / "sbom.json"
        orch = SbomOrchestrator("syft", tmp_path, timeout=10, retries=1)

        fake_result = MagicMock(stdout='{"bomFormat":"CycloneDX"}')
        with patch("subprocess.run", return_value=fake_result) as mock_run:
            result = orch.generate_sbom("platform", [tmp_path], out_file)

        assert result is True
        assert out_file.read_text() == '{"bomFormat":"CycloneDX"}'
        mock_run.assert_called_once()

    def test_generate_sbom_passes_excludes(self, tmp_path):
        SbomOrchestrator = _get_orch_class()
        out_file = tmp_path / "sbom.json"
        orch = SbomOrchestrator("syft", tmp_path, timeout=10, retries=1)

        fake_result = MagicMock(stdout="{}")
        with patch("subprocess.run", return_value=fake_result) as mock_run:
            orch.generate_sbom("platform", [tmp_path], out_file, excludes=["**/log/**"])

        cmd_args = mock_run.call_args[0][0]
        assert "--exclude" in cmd_args
        assert "**/log/**" in cmd_args

    def test_returns_false_for_empty_targets(self, tmp_path):
        SbomOrchestrator = _get_orch_class()
        orch = SbomOrchestrator("syft", tmp_path)
        assert orch.generate_sbom("apps", [], tmp_path / "out.json") is False


class TestSbomOrchestratorRetry:
    def test_retries_on_subprocess_failure(self, tmp_path):
        SbomOrchestrator = _get_orch_class()
        out_file = tmp_path / "sbom.json"
        orch = SbomOrchestrator("syft", tmp_path, timeout=10, retries=3)

        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise subprocess.CalledProcessError(1, "syft", stderr="fail")
            return MagicMock(stdout="{}")

        with patch("subprocess.run", side_effect=side_effect), \
             patch("time.sleep"):
            result = orch.generate_sbom("apps", [tmp_path], out_file)

        assert result is True
        assert call_count == 3

    def test_exhausts_retries_returns_false(self, tmp_path):
        SbomOrchestrator = _get_orch_class()
        out_file = tmp_path / "sbom.json"
        orch = SbomOrchestrator("syft", tmp_path, timeout=10, retries=2)

        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "syft", stderr="err")), \
             patch("time.sleep"):
            result = orch.generate_sbom("all", [tmp_path], out_file)

        assert result is False
        assert not out_file.exists()

    def test_retries_on_timeout(self, tmp_path):
        SbomOrchestrator = _get_orch_class()
        out_file = tmp_path / "sbom.json"
        orch = SbomOrchestrator("syft", tmp_path, timeout=1, retries=2)

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("syft", 1)), \
             patch("time.sleep"):
            result = orch.generate_sbom("platform", [tmp_path], out_file)

        assert result is False
