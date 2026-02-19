"""Tests for structured JSON logging and correlation IDs."""
import json
import logging

import pytest


def _dk():
    from conftest import dk
    return dk


class TestStructuredLogging:
    def test_run_id_is_set(self):
        dk = _dk()
        assert hasattr(dk, "RUN_ID")
        assert isinstance(dk.RUN_ID, str)
        assert len(dk.RUN_ID) == 12

    def test_json_formatter_produces_valid_json(self):
        dk = _dk()
        formatter = dk._JsonFormatter()
        record = logging.LogRecord(
            name="dk", level=logging.INFO, pathname="", lineno=0,
            msg="test message", args=(), exc_info=None,
        )
        record.run_id = "abc123"
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["msg"] == "test message"
        assert parsed["level"] == "INFO"
        assert parsed["run_id"] == "abc123"
        assert "ts" in parsed

    def test_json_formatter_handles_exception(self):
        dk = _dk()
        formatter = dk._JsonFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            import sys
            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="dk", level=logging.ERROR, pathname="", lineno=0,
            msg="err", args=(), exc_info=exc_info,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "exc" in parsed
        assert "boom" in parsed["exc"]

    def test_correlated_logger_adapter_injects_run_id(self):
        dk = _dk()
        # The module-level logger should be a _CorrelatedLoggerAdapter
        assert isinstance(dk.logger, dk._CorrelatedLoggerAdapter)
        assert dk.logger.extra["run_id"] == dk.RUN_ID


class TestResilienceDefaults:
    def test_defaults_are_sane(self):
        dk = _dk()
        assert dk.SUBPROCESS_TIMEOUT_SECS > 0
        assert dk.SUBPROCESS_RETRIES >= 1
        assert dk.THREAD_POOL_MAX_WORKERS >= 1
