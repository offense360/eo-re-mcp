# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""re-mcp-ghidra package — Ghidra backend for re-mcp.

Provides a lazy ``bootstrap()`` function that imports ``pyghidra`` and
starts the Ghidra JVM.  Workers call ``bootstrap()`` at startup before
any Ghidra Java class imports.  The supervisor process never calls it.
"""

from __future__ import annotations

import dataclasses
import functools
import glob
import json
import logging
import os
import platform
import sys

import re_mcp
from re_mcp import (  # noqa: F401  — re-export for backward compatibility
    ensure_run_id,
    get_version,
    resolve_log_file,
)

log = logging.getLogger(__name__)

#: Backend environment-variable prefix used for ``GHIDRA_MCP_LOG_LEVEL``,
#: ``GHIDRA_MCP_LOG_DIR``, ``GHIDRA_MCP_LOG_RUN`` and ``GHIDRA_MCP_LABEL``.
ENV_PREFIX = "GHIDRA_MCP_"

#: ``re_mcp.configure_logging`` bound to this backend's prefix.  Worker
#: processes call this with no arguments, so binding the prefix here is
#: what makes ``GHIDRA_MCP_*`` variables take effect inside workers.
configure_logging = functools.partial(re_mcp.configure_logging, env_prefix=ENV_PREFIX)

#: Source labels used by :func:`locate_ghidra` (fixed strings — tests search on them).
SOURCE_ENV = "GHIDRA_INSTALL_DIR"
SOURCE_PLATFORM = "platform default"


@dataclasses.dataclass(frozen=True)
class GhidraCandidate:
    """One installation-directory value that discovery actually checked."""

    source: str
    """Where the value came from — ``GHIDRA_INSTALL_DIR``,
    ``ghidra-config.json (<file>)``, ``platform default`` or ``lastrun (<file>)``."""
    path: str
    """The configured value, verbatim (never empty)."""
    exists: bool
    """Result of ``os.path.isdir(path)``."""


@dataclasses.dataclass(frozen=True)
class GhidraSearch:
    """Result of :func:`locate_ghidra` — the chosen path plus everything checked."""

    path: str | None
    """First candidate whose directory exists, or ``None``."""
    candidates: tuple[GhidraCandidate, ...]
    """Candidates in check order.  Discovery stops at the first hit, so
    sources after it are not listed."""
    unavailable: tuple[str, ...]
    """Sources that had no value to check, e.g. ``GHIDRA_INSTALL_DIR: not set``."""
    default_patterns: tuple[str, ...] = ()
    """Glob patterns behind the ``platform default`` source (for :meth:`describe`)."""
    checked_defaults: bool = False
    """Whether discovery got as far as the platform defaults."""

    def describe(self) -> str:
        """One line, ``; ``-separated, in check order — for log and error messages."""
        parts: list[str] = []
        default_hit: str | None = None
        for c in self.candidates:
            if c.source == SOURCE_PLATFORM:
                if c.exists:
                    default_hit = c.path
                continue
            state = "found" if c.exists else "does not exist"
            parts.append(f"{c.source}={c.path} ({state})")
        if self.checked_defaults:
            patterns = ", ".join(self.default_patterns)
            result = f"found {default_hit}" if default_hit else "no match"
            parts.append(f"{SOURCE_PLATFORM}: {patterns} ({result})")
        parts.extend(self.unavailable)
        return "; ".join(sorted(parts, key=_source_rank))


def _source_rank(text: str) -> int:
    """Sort key that restores check order for :meth:`GhidraSearch.describe`."""
    if text.startswith(SOURCE_ENV):
        return 0
    if text.startswith("ghidra-config.json"):
        return 1
    if text.startswith(SOURCE_PLATFORM):
        return 2
    return 3


def _user_home() -> str:
    """Home directory used for config, lastrun and platform-default lookups."""
    return os.path.expanduser("~")


def _config_path() -> str:
    return os.path.join(_user_home(), ".ghidra", "ghidra-config.json")


def _lastrun_path() -> str:
    """Path of pyghidra's ``lastrun`` file — mirrors pyghidra 3.1.0 launcher._lastrun().

    ``XDG_CONFIG_HOME`` wins on every platform; otherwise ``%APPDATA%`` on
    Windows (falling back to the home directory if ``APPDATA`` is unset),
    ``~/Library`` on macOS and ``~/.config`` elsewhere.  pyghidra itself is
    not imported here because the supervisor calls this too.
    """
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        base = xdg
    elif platform.system() == "Windows":
        base = os.environ.get("APPDATA") or _user_home()
    elif platform.system() == "Darwin":
        base = os.path.join(_user_home(), "Library")
    else:
        base = os.path.join(_user_home(), ".config")
    return os.path.join(base, "ghidra", "lastrun")


def locate_ghidra() -> GhidraSearch:
    """Find the Ghidra installation directory and report every source checked.

    Search order:
      1. ``GHIDRA_INSTALL_DIR`` environment variable
      2. ``ghidra-install-dir`` from ``~/.ghidra/ghidra-config.json``
      3. Platform-specific default installation paths
      4. pyghidra's ``lastrun`` file (what pyghidra falls back to on its own)

    A configured source (1, 2 or 4) whose directory is missing is logged as a
    WARNING and skipped.  This is the only place discovery warns, so callers
    do not repeat the message.
    """
    candidates: list[GhidraCandidate] = []
    unavailable: list[str] = []
    patterns = tuple(_platform_default_patterns())

    def result(path: str | None, checked_defaults: bool) -> GhidraSearch:
        return GhidraSearch(path, tuple(candidates), tuple(unavailable), patterns, checked_defaults)

    def check(source: str, path: str) -> bool:
        exists = os.path.isdir(path)
        candidates.append(GhidraCandidate(source=source, path=path, exists=exists))
        if not exists and source != SOURCE_PLATFORM:
            log.warning("%s points at %s, which does not exist; ignoring it", source, path)
        return exists

    # 1. environment variable
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env:
        if check(SOURCE_ENV, env):
            return result(env, False)
    else:
        unavailable.append(f"{SOURCE_ENV}: not set")

    # 2. config file
    config_file = _config_path()
    config_source = f"ghidra-config.json ({config_file})"
    if os.path.isfile(config_file):
        value, error = _read_ghidra_config(config_file)
        if error is not None:
            log.warning("%s could not be read (%s); ignoring it", config_source, error)
            unavailable.append(f"{config_source}: unreadable")
        elif value:
            if check(config_source, value):
                return result(value, False)
        else:
            unavailable.append(f"{config_source}: no ghidra-install-dir key")
    else:
        unavailable.append(f"{config_source}: not present")

    # 3. platform defaults
    for d in _platform_default_dirs(patterns):
        if check(SOURCE_PLATFORM, d):
            return result(d, True)

    # 4. pyghidra lastrun
    lastrun_file = _lastrun_path()
    lastrun_source = f"lastrun ({lastrun_file})"
    lastrun_value = _read_lastrun(lastrun_file)
    if lastrun_value is None:
        unavailable.append(f"{lastrun_source}: not present")
    elif not lastrun_value:
        unavailable.append(f"{lastrun_source}: empty")
    elif check(lastrun_source, lastrun_value):
        return result(lastrun_value, True)

    return result(None, True)


def find_ghidra_dir() -> str | None:
    """Return the Ghidra installation directory, or ``None`` if not found.

    Thin wrapper over :func:`locate_ghidra` kept for existing callers.
    """
    return locate_ghidra().path


def _read_ghidra_config(config_path: str) -> tuple[str | None, str | None]:
    """Read ``ghidra-install-dir`` from *config_path*.

    Returns ``(value, None)`` on success (``value`` is ``None`` when the key
    is absent or empty) or ``(None, error_text)`` when the file cannot be
    read or parsed.
    """
    try:
        with open(config_path, encoding="utf-8") as f:
            config = json.load(f)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        return None, f"{type(exc).__name__}: {exc}"
    if not isinstance(config, dict):
        return None, "top-level JSON value is not an object"
    value = config.get("ghidra-install-dir")
    return (str(value) if value else None), None


def _read_lastrun(lastrun_file: str) -> str | None:
    """First line of pyghidra's lastrun file, stripped; ``None`` if absent/unreadable."""
    if not os.path.isfile(lastrun_file):
        return None
    try:
        with open(lastrun_file, encoding="utf-8") as f:
            return f.readline().strip()
    except (OSError, UnicodeDecodeError) as exc:
        log.warning("lastrun (%s) could not be read (%s); ignoring it", lastrun_file, exc)
        return None


def _platform_default_patterns() -> list[str]:
    """Glob patterns for default Ghidra install locations on the current platform."""
    plat = sys.platform
    home = _user_home()
    if plat == "darwin":
        return ["/Applications/ghidra_*", os.path.join(home, "ghidra_*")]
    if plat == "win32":
        return [r"C:\ghidra_*", os.path.join(home, "ghidra_*")]
    return ["/opt/ghidra_*", "/usr/local/ghidra_*", os.path.join(home, "ghidra_*")]


def _platform_default_dirs(patterns: tuple[str, ...] | list[str] | None = None) -> list[str]:
    """Return candidate Ghidra install directories for the current platform."""
    if patterns is None:
        patterns = _platform_default_patterns()
    candidates: list[str] = []
    for pattern in patterns:
        candidates += glob.glob(pattern)
    return sorted(candidates, reverse=True)


_bootstrapped = False


def bootstrap():
    """Ensure pyghidra is imported and the Ghidra JVM is started.

    Must be called before any Ghidra Java class is imported.  Called once
    by ``server.main()`` at worker startup.  The supervisor never calls this.
    """
    global _bootstrapped  # noqa: PLW0603
    if _bootstrapped:
        return

    log.debug("Bootstrapping pyghidra...")

    search = locate_ghidra()
    if search.path is None:
        # Our search covers both sources pyghidra would consult on its own
        # (GHIDRA_INSTALL_DIR and lastrun), so there is nothing left for it
        # to find — fail here with the full list instead of letting pyghidra
        # abort the worker with a bare "GHIDRA_INSTALL_DIR is not set".
        raise RuntimeError(
            f"Ghidra installation not found. Checked: {search.describe()}. "
            "Set GHIDRA_INSTALL_DIR to your Ghidra directory."
        )
    source = next(c.source for c in search.candidates if c.exists)
    previous = os.environ.get("GHIDRA_INSTALL_DIR")
    if previous is not None and previous != search.path:
        log.info("Replacing GHIDRA_INSTALL_DIR=%s with %s", previous, search.path)
    # Always export: pyghidra reads GHIDRA_INSTALL_DIR itself, so a stale
    # value left in the environment would otherwise win over what we found.
    os.environ["GHIDRA_INSTALL_DIR"] = search.path
    log.debug("Using Ghidra installation at %s (from %s)", search.path, source)

    try:
        from pyghidra.launcher import HeadlessPyGhidraLauncher  # noqa: PLC0415
    except ImportError:
        raise ImportError(
            "Could not find the pyghidra package.\n"
            "Install pyghidra and ensure Ghidra is installed:\n"
            "  pip install pyghidra\n"
            "Then either:\n"
            "  - Set the GHIDRA_INSTALL_DIR environment variable, or\n"
            "  - Place Ghidra in a standard location (/opt/ghidra_*, ~/ghidra_*)"
        ) from None

    try:
        launcher = HeadlessPyGhidraLauncher()
    except ValueError as exc:
        # Directory exists but pyghidra's own validation failed (missing
        # application.properties, PyGhidra module, ...).
        raise RuntimeError(
            f"pyghidra rejected the Ghidra installation at {search.path} (from {source}): {exc}"
        ) from exc
    _NATIVE_ACCESS_ARG = "--enable-native-access=ALL-UNNAMED"
    if _NATIVE_ACCESS_ARG not in launcher.vm_args:
        launcher.vm_args.append(_NATIVE_ACCESS_ARG)
    launcher.start()
    log.info("pyghidra bootstrapped successfully")

    _bootstrapped = True
