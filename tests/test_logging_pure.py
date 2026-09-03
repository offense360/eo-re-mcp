# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Unit tests for log-path resolution and run-ID propagation."""

from __future__ import annotations

import logging
import os

import pytest
import re_mcp
import re_mcp_ghidra
import re_mcp_ida
from re_mcp import _sanitize_label, ensure_run_id, resolve_log_file

_PREFIXES = ("RE_MCP_", "IDA_MCP_", "GHIDRA_MCP_")
_NAMES = ("LOG_RUN", "LOG_DIR", "LOG_LEVEL", "LABEL")


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    for prefix in _PREFIXES:
        for name in _NAMES:
            monkeypatch.delenv(f"{prefix}{name}", raising=False)
    # Reset the process-wide prefix so tests that bind a backend prefix
    # don't leak into later tests.
    monkeypatch.setattr(re_mcp, "_ENV_PREFIX", "RE_MCP_", raising=False)
    root = logging.getLogger()
    saved = list(root.handlers)
    yield
    for handler in list(root.handlers):
        if handler not in saved:
            root.removeHandler(handler)
            handler.close()


def test_resolve_log_file_unset_returns_none():
    assert resolve_log_file("supervisor") is None


def test_resolve_log_file_builds_path(monkeypatch, tmp_path):
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(tmp_path))
    result = resolve_log_file("supervisor")
    assert result is not None
    assert os.path.dirname(result) == str(tmp_path)
    assert result.endswith("-supervisor.log")
    run_id = os.environ["RE_MCP_LOG_RUN"]
    assert os.path.basename(result) == f"{run_id}-supervisor.log"


def test_resolve_log_file_custom_suffix(monkeypatch, tmp_path):
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(tmp_path))
    result = resolve_log_file("worker-abc", suffix=".stderr")
    assert result.endswith("-worker-abc.stderr")


def test_resolve_log_file_creates_missing_directory(monkeypatch, tmp_path):
    target = tmp_path / "nested" / "logs"
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(target))
    result = resolve_log_file("supervisor")
    assert os.path.isdir(target)
    assert result.startswith(str(target))


def test_resolve_log_file_sanitizes_label(monkeypatch, tmp_path):
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(tmp_path))
    # Path separators must not leak into the filename — the resolved path
    # must stay inside the configured directory.
    result = resolve_log_file("worker-../evil/db")
    assert os.path.dirname(result) == str(tmp_path)
    assert os.sep not in os.path.basename(result)


def test_resolve_log_file_empty_label(monkeypatch, tmp_path):
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(tmp_path))
    result = resolve_log_file("")
    run_id = os.environ["RE_MCP_LOG_RUN"]
    assert os.path.basename(result) == f"{run_id}.log"


def test_resolve_log_file_shares_run_id_across_calls(monkeypatch, tmp_path):
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(tmp_path))
    first = resolve_log_file("supervisor")
    second = resolve_log_file("worker-x")
    prefix_first = os.path.basename(first).split("-supervisor")[0]
    prefix_second = os.path.basename(second).split("-worker-x")[0]
    assert prefix_first == prefix_second


def test_ensure_run_id_respects_preexisting_env(monkeypatch):
    monkeypatch.setenv("RE_MCP_LOG_RUN", "preset-run-id")
    assert ensure_run_id() == "preset-run-id"


def test_ensure_run_id_generates_and_persists():
    run_id = ensure_run_id()
    assert run_id
    assert os.environ["RE_MCP_LOG_RUN"] == run_id
    assert ensure_run_id() == run_id


def test_sanitize_label_replaces_unsafe_chars():
    # Dots are kept (safe in a leaf filename); separators are scrubbed.
    assert _sanitize_label("worker/db.i64") == "worker_db.i64"
    assert _sanitize_label("safe-label_1.2") == "safe-label_1.2"
    assert _sanitize_label("a b:c") == "a_b_c"
    assert "/" not in _sanitize_label("../evil/x")


# ---------------------------------------------------------------------------
# Backend env prefix (issue #3)
# ---------------------------------------------------------------------------


def _file_handlers() -> list[logging.FileHandler]:
    return [h for h in logging.getLogger().handlers if isinstance(h, logging.FileHandler)]


def test_resolve_log_file_honors_backend_prefix(monkeypatch, tmp_path):
    re_mcp.set_env_prefix("GHIDRA_MCP_")
    monkeypatch.setenv("GHIDRA_MCP_LOG_DIR", str(tmp_path))
    result = resolve_log_file("supervisor")
    assert result is not None
    assert os.path.dirname(result) == str(tmp_path)


def test_ensure_run_id_reads_backend_prefix(monkeypatch):
    re_mcp.set_env_prefix("GHIDRA_MCP_")
    monkeypatch.setenv("GHIDRA_MCP_LOG_RUN", "ghidra-run-id")
    assert ensure_run_id() == "ghidra-run-id"


def test_ensure_run_id_persists_under_backend_prefix():
    re_mcp.set_env_prefix("GHIDRA_MCP_")
    run_id = ensure_run_id()
    assert os.environ["GHIDRA_MCP_LOG_RUN"] == run_id
    assert ensure_run_id() == run_id


def test_run_id_shared_between_prefixed_dir_and_run(monkeypatch, tmp_path):
    # A worker started by a Ghidra supervisor sees GHIDRA_MCP_LOG_RUN and
    # GHIDRA_MCP_LOG_DIR only; its file must use the inherited run id.
    re_mcp.set_env_prefix("GHIDRA_MCP_")
    monkeypatch.setenv("GHIDRA_MCP_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("GHIDRA_MCP_LOG_RUN", "inherited")
    result = resolve_log_file("worker-x")
    assert os.path.basename(result) == "inherited-worker-x.log"


def test_env_precedence_prefix_then_re_mcp_then_ida(monkeypatch, tmp_path):
    re_mcp.set_env_prefix("GHIDRA_MCP_")
    ghidra_dir = tmp_path / "ghidra"
    re_dir = tmp_path / "re"
    ida_dir = tmp_path / "ida"
    monkeypatch.setenv("GHIDRA_MCP_LOG_DIR", str(ghidra_dir))
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(re_dir))
    monkeypatch.setenv("IDA_MCP_LOG_DIR", str(ida_dir))
    assert os.path.dirname(resolve_log_file("s")) == str(ghidra_dir)

    monkeypatch.delenv("GHIDRA_MCP_LOG_DIR")
    assert os.path.dirname(resolve_log_file("s")) == str(re_dir)

    monkeypatch.delenv("RE_MCP_LOG_DIR")
    assert os.path.dirname(resolve_log_file("s")) == str(ida_dir)


def test_explicit_env_key_still_overrides_prefix(monkeypatch, tmp_path):
    re_mcp.set_env_prefix("GHIDRA_MCP_")
    custom = tmp_path / "custom"
    monkeypatch.setenv("GHIDRA_MCP_LOG_DIR", str(tmp_path / "ghidra"))
    monkeypatch.setenv("MY_LOG_DIR", str(custom))
    assert os.path.dirname(resolve_log_file("s", env_key="MY_LOG_DIR")) == str(custom)


def test_configure_logging_binds_prefix_for_later_calls(monkeypatch, tmp_path):
    # configure_logging(env_prefix=...) is what the supervisor calls; every
    # later resolve_log_file() in the same process must see that prefix.
    monkeypatch.setenv("GHIDRA_MCP_LOG_DIR", str(tmp_path))
    re_mcp.configure_logging(label="supervisor", env_prefix="GHIDRA_MCP_")
    result = resolve_log_file("worker-x", suffix=".stderr")
    assert result is not None
    assert os.path.dirname(result) == str(tmp_path)
    assert any(os.path.dirname(h.baseFilename) == str(tmp_path) for h in _file_handlers())


def test_configure_logging_without_prefix_keeps_current(monkeypatch, tmp_path):
    re_mcp.set_env_prefix("GHIDRA_MCP_")
    monkeypatch.setenv("GHIDRA_MCP_LOG_DIR", str(tmp_path))
    re_mcp.configure_logging(label="x")
    assert resolve_log_file("y") is not None


def test_ghidra_wrapper_binds_prefix(monkeypatch, tmp_path):
    # The worker calls re_mcp_ghidra.configure_logging() with no arguments
    # and only GHIDRA_MCP_* variables in its environment.
    monkeypatch.setenv("GHIDRA_MCP_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("GHIDRA_MCP_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("GHIDRA_MCP_LABEL", "worker-where")
    monkeypatch.setenv("GHIDRA_MCP_LOG_RUN", "run123")
    re_mcp_ghidra.configure_logging()
    handlers = [h for h in _file_handlers() if os.path.dirname(h.baseFilename) == str(tmp_path)]
    assert len(handlers) == 1
    assert os.path.basename(handlers[0].baseFilename) == "run123-worker-where.log"
    assert handlers[0].level == logging.DEBUG


def test_ida_wrapper_binds_prefix(monkeypatch, tmp_path):
    # IDA_MCP_* must win over RE_MCP_* inside an IDA worker; before the
    # wrapper bound the prefix, RE_MCP_LOG_DIR took precedence.
    ida_dir = tmp_path / "ida"
    re_dir = tmp_path / "re"
    monkeypatch.setenv("IDA_MCP_LOG_DIR", str(ida_dir))
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(re_dir))
    monkeypatch.setenv("IDA_MCP_LOG_RUN", "ida-run")
    monkeypatch.setenv("RE_MCP_LOG_RUN", "re-run")
    re_mcp_ida.configure_logging(label="worker-db")
    handlers = [h for h in _file_handlers() if os.path.dirname(h.baseFilename) == str(ida_dir)]
    assert len(handlers) == 1
    assert os.path.basename(handlers[0].baseFilename) == "ida-run-worker-db.log"
