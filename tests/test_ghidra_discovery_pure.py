# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Pure unit tests for Ghidra installation discovery (issue #17) — no Ghidra required.

Covers ``re_mcp_ghidra.locate_ghidra`` / ``GhidraSearch``, the ``bootstrap()``
environment handling, and the supervisor-side pre-check in
``re_mcp_ghidra.backend``.  Every source the discovery reads (env var, config
file, platform defaults, pyghidra's ``lastrun`` file) is redirected into
``tmp_path`` so the developer's real configuration is never touched.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from types import ModuleType
from typing import ClassVar
from unittest.mock import MagicMock

import pytest
import re_mcp_ghidra
from fastmcp import Client, FastMCP
from re_mcp_ghidra import GhidraSearch, find_ghidra_dir, locate_ghidra
from re_mcp_ghidra.backend import GhidraBackend, _require_ghidra_dir
from re_mcp_ghidra.exceptions import GhidraError

LOGGER = "re_mcp_ghidra"


class _Isolated:
    """Handle returned by the ``isolated`` fixture: paths plus small writers."""

    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.home = tmp_path / "home"
        self.xdg = tmp_path / "xdg"
        self.defaults = tmp_path / "defaults"
        self.config_file = self.home / ".ghidra" / "ghidra-config.json"
        self.lastrun_file = self.xdg / "ghidra" / "lastrun"
        self.missing = str(tmp_path / "gone" / "ghidra_0.0.0_PUBLIC")

    def make_dir(self, name: str) -> str:
        d = self.tmp_path / name
        d.mkdir(parents=True, exist_ok=True)
        return str(d)

    def write_config(self, path_value: str) -> str:
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.config_file.write_text(
            json.dumps({"ghidra-install-dir": path_value}), encoding="utf-8"
        )
        return str(self.config_file)

    def write_raw_config(self, text: str) -> str:
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.config_file.write_text(text, encoding="utf-8")
        return str(self.config_file)

    def write_lastrun(self, path_value: str) -> str:
        self.lastrun_file.parent.mkdir(parents=True, exist_ok=True)
        self.lastrun_file.write_text(path_value + "\n", encoding="utf-8")
        return str(self.lastrun_file)


@pytest.fixture
def isolated(monkeypatch, tmp_path) -> _Isolated:
    iso = _Isolated(tmp_path)
    iso.home.mkdir()
    iso.xdg.mkdir()
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.setenv("USERPROFILE", str(iso.home))
    monkeypatch.setenv("HOME", str(iso.home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(iso.xdg))
    monkeypatch.setattr(
        re_mcp_ghidra,
        "_platform_default_patterns",
        lambda: [str(iso.defaults / "ghidra_*")],
    )
    return iso


def _warnings(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]


# ---------------------------------------------------------------------------
# locate_ghidra() — precedence and warnings
# ---------------------------------------------------------------------------


def test_valid_env_wins_without_warning(isolated, monkeypatch, caplog):
    good = isolated.make_dir("ghidra_env")
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", good)
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        search = locate_ghidra()
    assert isinstance(search, GhidraSearch)
    assert search.path == good
    assert _warnings(caplog) == []
    assert f"GHIDRA_INSTALL_DIR={good} (found)" in search.describe()


def test_stale_env_warns_and_falls_through_to_config(isolated, monkeypatch, caplog):
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", isolated.missing)
    good = isolated.make_dir("ghidra_cfg")
    isolated.write_config(good)
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        search = locate_ghidra()
    assert search.path == good
    warnings = _warnings(caplog)
    assert len(warnings) == 1
    assert "GHIDRA_INSTALL_DIR" in warnings[0]
    assert isolated.missing in warnings[0]


def test_stale_config_warns_and_falls_through_to_default(isolated, caplog):
    isolated.write_config(isolated.missing)
    isolated.defaults.mkdir()
    default = isolated.make_dir("defaults/ghidra_1")
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        search = locate_ghidra()
    assert search.path == default
    warnings = _warnings(caplog)
    assert any("ghidra-config.json (" in w and isolated.missing in w for w in warnings)


def test_lastrun_is_last_resort(isolated, caplog):
    good = isolated.make_dir("ghidra_lastrun")
    isolated.write_lastrun(good)
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        search = locate_ghidra()
    assert search.path == good
    assert _warnings(caplog) == []


def test_lastrun_does_not_outrank_platform_default(isolated):
    a = isolated.make_dir("ghidra_a")
    isolated.write_lastrun(a)
    isolated.defaults.mkdir()
    b = isolated.make_dir("defaults/ghidra_b")
    assert locate_ghidra().path == b


def test_stale_lastrun_warns(isolated, caplog):
    isolated.write_lastrun(isolated.missing)
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        search = locate_ghidra()
    assert search.path is None
    warnings = _warnings(caplog)
    assert any("lastrun (" in w and isolated.missing in w for w in warnings)


def test_unreadable_config_warns_and_continues(isolated, caplog):
    isolated.write_raw_config("{not json")
    isolated.defaults.mkdir()
    default = isolated.make_dir("defaults/ghidra_1")
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        search = locate_ghidra()
    assert search.path == default
    assert any("ghidra-config.json" in w for w in _warnings(caplog))
    assert "unreadable" in search.describe()


# ---------------------------------------------------------------------------
# describe()
# ---------------------------------------------------------------------------


def test_nothing_found_describe_lists_every_source(isolated, monkeypatch):
    env_missing = str(isolated.tmp_path / "gone" / "env")
    cfg_missing = str(isolated.tmp_path / "gone" / "cfg")
    lr_missing = str(isolated.tmp_path / "gone" / "lastrun")
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", env_missing)
    isolated.write_config(cfg_missing)
    isolated.write_lastrun(lr_missing)
    search = locate_ghidra()
    assert search.path is None
    text = search.describe()
    for p in (env_missing, cfg_missing, lr_missing):
        assert p in text
    assert text.count("does not exist") == 3
    assert "platform default:" in text
    assert "(no match)" in text


def test_nothing_configured_describe_says_so(isolated):
    search = locate_ghidra()
    assert search.path is None
    text = search.describe()
    assert "GHIDRA_INSTALL_DIR: not set" in text
    assert text.count("not present") == 2


def test_find_ghidra_dir_matches_locate(isolated, monkeypatch):
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", isolated.missing)
    good = isolated.make_dir("ghidra_cfg")
    isolated.write_config(good)
    assert find_ghidra_dir() == locate_ghidra().path == good


# ---------------------------------------------------------------------------
# backend.py — supervisor-side pre-check
# ---------------------------------------------------------------------------


def test_require_ghidra_dir_raises_not_found_with_locations(isolated):
    with pytest.raises(GhidraError) as ei:
        _require_ghidra_dir()
    assert ei.value.error_type == "NotFound"
    message = ei.value.args[0]
    assert "Checked:" in message
    assert "GHIDRA_INSTALL_DIR" in message


def test_register_management_tools_logs_error_when_missing(isolated, caplog):
    with caplog.at_level(logging.ERROR, logger="re_mcp_ghidra.backend"):
        GhidraBackend.register_management_tools(FastMCP("t"), MagicMock())
    errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert any("Ghidra installation not found" in m for m in errors)


@pytest.mark.asyncio
async def test_open_database_tool_fails_before_spawning_worker(isolated):
    mcp = FastMCP("t")
    pool = MagicMock()
    pool.open_database = MagicMock()  # would be awaited if reached
    GhidraBackend.register_management_tools(mcp, pool)
    async with Client(mcp) as client:
        result = await client.call_tool(
            "open_database",
            {"file_path": str(isolated.tmp_path / "bin.exe")},
            raise_on_error=False,
        )
    assert result.is_error
    text = " ".join(getattr(c, "text", "") for c in result.content)
    assert "NotFound" in text
    assert "Checked:" in text
    pool.open_database.assert_not_called()


# ---------------------------------------------------------------------------
# bootstrap() — env export and fail-fast
# ---------------------------------------------------------------------------


class _FakeLauncher:
    """Stand-in for ``pyghidra.launcher.HeadlessPyGhidraLauncher``."""

    instances: ClassVar[list[_FakeLauncher]] = []
    raise_on_init: ClassVar[Exception | None] = None

    def __init__(self):
        if _FakeLauncher.raise_on_init is not None:
            raise _FakeLauncher.raise_on_init
        self.seen_env = os.environ.get("GHIDRA_INSTALL_DIR")
        self.vm_args: list[str] = []
        _FakeLauncher.instances.append(self)

    def start(self):
        pass


@pytest.fixture
def fake_pyghidra(monkeypatch):
    _FakeLauncher.instances = []
    _FakeLauncher.raise_on_init = None
    pkg = ModuleType("pyghidra")
    launcher = ModuleType("pyghidra.launcher")
    launcher.HeadlessPyGhidraLauncher = _FakeLauncher
    pkg.launcher = launcher
    monkeypatch.setitem(sys.modules, "pyghidra", pkg)
    monkeypatch.setitem(sys.modules, "pyghidra.launcher", launcher)
    monkeypatch.setattr(re_mcp_ghidra, "_bootstrapped", False)
    return _FakeLauncher


def test_bootstrap_overrides_stale_env(isolated, monkeypatch, fake_pyghidra):
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", isolated.missing)
    good = isolated.make_dir("ghidra_cfg")
    isolated.write_config(good)
    re_mcp_ghidra.bootstrap()
    assert len(fake_pyghidra.instances) == 1
    assert fake_pyghidra.instances[0].seen_env == good


def test_bootstrap_not_found_raises_before_pyghidra(isolated, fake_pyghidra):
    with pytest.raises(RuntimeError) as ei:
        re_mcp_ghidra.bootstrap()
    assert "Checked:" in str(ei.value)
    assert fake_pyghidra.instances == []


def test_bootstrap_wraps_pyghidra_rejection(isolated, monkeypatch, fake_pyghidra):
    good = isolated.make_dir("ghidra_env")
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", good)
    cause = ValueError("x does not exist")
    fake_pyghidra.raise_on_init = cause
    with pytest.raises(RuntimeError) as ei:
        re_mcp_ghidra.bootstrap()
    assert good in str(ei.value)
    assert "GHIDRA_INSTALL_DIR" in str(ei.value)
    assert ei.value.__cause__ is cause
