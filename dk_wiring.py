# Red Boss Discovery Kit — wiring-corpus pack emitter (ADR-0020)
#
# S44-02: emits the ADR-0019 wiring corpus *inside* the evidence pack as
# first-class derived artifacts — <run_out>/wiring/ — driven by the
# manifest's `wiring:` section. The extractor modules are vendored
# verbatim from the JBoss automation repo's ci/lib (the reference
# implementation and parity oracle); output must equal the interim
# channel's, which the S44-06 parity harness proves.
#
# Unlike the interim channel the extractors run in-process — a frozen
# (PyInstaller) binary has no usable sys.executable for subprocesses.

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import Any, Callable, Dict


def in_process_runner(script: str, args: list) -> bool:
    """Extractor transport for the pack channel: invoke each vendored
    module's main(argv) in-process. Mirrors subprocess_runner's
    contract (bool success; extractor prints to stderr itself)."""
    module_name = script.removesuffix(".py") if script.endswith(".py") \
        else script
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        print(f"dk_wiring: cannot import {module_name}: {exc}",
              file=sys.stderr)
        return False
    try:
        return module.main(list(args)) == 0
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 0
        if code != 0:
            print(f"dk_wiring: {script} exited {code}", file=sys.stderr)
        return code == 0
    except Exception as exc:  # noqa: BLE001 — report, don't crash the run
        print(f"dk_wiring: {script} raised {exc}", file=sys.stderr)
        return False


def emit(
    manifest: Dict[str, Any],
    run_out: Path,
    host: str,
    collection_mode: str = "live",
    locator_key_env: str = "RB_WIRING_LOCATOR_KEY",
    locator_key_file=None,
) -> int:
    """Emit the wiring corpus beneath <run_out>/wiring/ (in-pack).

    Returns wiring_emit.emit_corpus's status (0 ok / 1 failure —
    including the secrets-scan gate deleting artifacts while the
    manifest attests the failure).
    """
    import wiring_emit

    return wiring_emit.emit_corpus(
        manifest_path=None,
        manifest=manifest,
        output_dir=run_out,
        host=host,
        collection_mode=collection_mode,
        locator_key_env=locator_key_env,
        locator_key_file=locator_key_file,
        insecure_unkeyed=False,
        runner=in_process_runner,
        generator_name="dk-core wiring corpus",
    )
