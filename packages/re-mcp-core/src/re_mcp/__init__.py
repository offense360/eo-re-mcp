# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""re-mcp core package — shared infrastructure for reverse-engineering MCP backends."""

from __future__ import annotations

import datetime as _dt
import logging
import os
import re
import sys

log = logging.getLogger(__name__)


_DEFAULT_ENV_PREFIX = "RE_MCP_"
_ENV_PREFIX = _DEFAULT_ENV_PREFIX


def set_env_prefix(prefix: str) -> None:
    """Set the process-wide backend environment-variable prefix.

    ``configure_logging(env_prefix=...)`` calls this so that every later
    ``ensure_run_id`` / ``resolve_log_file`` call in the same process reads
    the backend's variables (e.g. ``GHIDRA_MCP_LOG_DIR``) without each
    call site having to thread the prefix through.
    """
    global _ENV_PREFIX  # noqa: PLW0603
    _ENV_PREFIX = prefix


def get_env_prefix() -> str:
    """Return the process-wide backend environment-variable prefix."""
    return _ENV_PREFIX


def _env_keys(name: str, env_key: str | None = None) -> list[str]:
    """Return lookup keys for ``name`` in precedence order.

    ``env_key`` (or ``{prefix}{name}``) first, then the backend-neutral
    ``RE_MCP_{name}``, then the legacy ``IDA_MCP_{name}``.
    """
    keys = [env_key or f"{_ENV_PREFIX}{name}", f"RE_MCP_{name}", f"IDA_MCP_{name}"]
    return list(dict.fromkeys(keys))


def _env_lookup(name: str, env_key: str | None = None) -> str | None:
    """Return the first non-empty value among :func:`_env_keys`."""
    for key in _env_keys(name, env_key):
        value = os.environ.get(key)
        if value:
            return value
    return None


def ensure_run_id(*, env_key: str | None = None) -> str:
    """Return a run ID shared across this supervisor and its workers.

    The supervisor generates the ID once and exports it via the environment
    so child worker processes inherit it and log to files with the same
    timestamp prefix.  ``env_key`` defaults to ``{prefix}LOG_RUN``; the
    backend-neutral ``RE_MCP_LOG_RUN`` and legacy ``IDA_MCP_LOG_RUN`` are
    accepted as fallbacks.
    """
    env_key = env_key or f"{_ENV_PREFIX}LOG_RUN"
    run_id = _env_lookup("LOG_RUN", env_key)
    if run_id:
        os.environ.setdefault(env_key, run_id)
        return run_id
    run_id = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    os.environ[env_key] = run_id
    return run_id


_UNSAFE_LABEL_RE = re.compile(r"[^\w.-]+")


def _sanitize_label(label: str) -> str:
    """Strip filesystem-unsafe characters from a log-file label component."""
    return _UNSAFE_LABEL_RE.sub("_", label)


def resolve_log_file(label: str, *, suffix: str = ".log", env_key: str | None = None) -> str | None:
    """Build a log-file path inside the configured log directory.

    Returns ``<dir>/<run_id>-<sanitized_label><suffix>`` or ``None`` when
    the log directory environment variable is unset.  ``env_key`` defaults
    to ``{prefix}LOG_DIR``, falling back to ``RE_MCP_LOG_DIR`` and the
    legacy ``IDA_MCP_LOG_DIR``.
    """
    log_dir = _env_lookup("LOG_DIR", env_key)
    if not log_dir:
        return None
    path = os.path.expanduser(log_dir)
    os.makedirs(path, exist_ok=True)
    run_id = ensure_run_id()
    safe_label = _sanitize_label(label)
    filename = f"{run_id}-{safe_label}{suffix}" if safe_label else f"{run_id}{suffix}"
    return os.path.join(path, filename)


def configure_logging(*, label: str = "", env_prefix: str | None = None) -> None:
    """Configure logging from environment variables.

    Reads ``{env_prefix}LOG_LEVEL`` (default WARNING) and optionally tees
    to a file under ``{env_prefix}LOG_DIR``.  Falls back to ``RE_MCP_`` and
    ``IDA_MCP_`` prefixed variables for backward compatibility.

    When ``env_prefix`` is given it becomes the process-wide prefix (see
    :func:`set_env_prefix`) so later ``resolve_log_file`` / ``ensure_run_id``
    calls in this process use it too.  When omitted, the current
    process-wide prefix (default ``RE_MCP_``) is used.
    """
    if env_prefix is not None:
        set_env_prefix(env_prefix)
    if not label:
        label = _env_lookup("LABEL") or ""
    level_name = (_env_lookup("LOG_LEVEL") or "WARNING").upper()
    level = getattr(logging, level_name, None)
    if not isinstance(level, int):
        level = logging.WARNING
    name_part = f"%(name)s ({label})" if label else "%(name)s"
    fmt = f"%(asctime)s [%(levelname)s] {name_part}: %(message)s"
    logging.basicConfig(
        level=level,
        format=fmt,
        stream=sys.stderr,
    )
    log_file = resolve_log_file(label or "supervisor")
    if log_file:
        root = logging.getLogger()
        if not any(
            isinstance(h, logging.FileHandler)
            and getattr(h, "baseFilename", None) == os.path.abspath(log_file)
            for h in root.handlers
        ):
            handler = logging.FileHandler(log_file, mode="a")
            handler.setLevel(level)
            handler.setFormatter(logging.Formatter(fmt))
            root.addHandler(handler)


def get_version(package: str = "re-mcp-core") -> str:
    """Return the installed package version, or ``"unknown"`` if unavailable."""
    from importlib.metadata import version as pkg_version  # noqa: PLC0415

    try:
        return pkg_version(package)
    except Exception:
        return "unknown"
