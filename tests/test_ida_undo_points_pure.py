# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Issue #26 — IDA undo semantics: one mutating tool call == one undo step.

``IDAServer.tool()`` creates an IDA undo point before every tool whose
annotations carry ``readOnlyHint: False`` (lifecycle/analysis tools
excepted), so ``undo`` reverts exactly one tool call.  These tests run
without idalib: ``ida_undo`` is a ``MagicMock`` stub from ``conftest`` and
the main-thread dispatch is short-circuited to an in-place call.
"""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import MagicMock

import ida_undo
import pytest
import re_mcp_ida.helpers as ida_helpers
from re_mcp.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_MUTATE_NON_IDEMPOTENT,
    ANNO_READ_ONLY,
)
from re_mcp_ida.server import UNDO_POINT_EXEMPT, IDAServer
from re_mcp_ida.session import session

_TOOLS_DIR = Path(__file__).resolve().parents[1] / "packages/re-mcp-ida/src/re_mcp_ida/tools"


async def _run_inline(fn, *args, **kwargs):
    """Stand-in for the main-thread dispatch: call *fn* right here."""
    return fn(*args, **kwargs)


@pytest.fixture
def srv(monkeypatch):
    """An ``IDAServer`` whose main-thread dispatch runs in place."""
    monkeypatch.setattr(IDAServer, "_dispatch", lambda self, fn, *a, **k: _run_inline(fn, *a, **k))
    monkeypatch.setattr(session, "_current_path", "C:/fake/db.i64")
    return IDAServer("t")


@pytest.fixture
def create_undo_point(monkeypatch):
    mock = MagicMock(return_value=True)
    monkeypatch.setattr(ida_undo, "create_undo_point", mock)
    return mock


async def _call(srv: IDAServer, tool_name: str, **kwargs):
    tool = await srv.get_tool(tool_name)
    return await tool.fn(**kwargs)


# ---------------------------------------------------------------------------
# Which tools get an undo point
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mutating_tool_creates_undo_point_before_running(srv, create_undo_point):
    order: list[str] = []
    create_undo_point.side_effect = lambda *_a: order.append("undo_point") or True

    @srv.tool(annotations=ANNO_MUTATE, tags={"x"})
    def rename_thing(name: str) -> str:
        """Rename a thing."""
        order.append("body")
        return name

    assert await _call(srv, "rename_thing", name="n") == "n"
    create_undo_point.assert_called_once_with("re-mcp", "rename_thing")
    assert order == ["undo_point", "body"]


@pytest.mark.asyncio
async def test_read_only_tool_creates_no_undo_point(srv, create_undo_point):
    @srv.tool(annotations=ANNO_READ_ONLY, tags={"x"})
    def get_thing() -> str:
        """Get a thing."""
        return "ok"

    assert await _call(srv, "get_thing") == "ok"
    create_undo_point.assert_not_called()


@pytest.mark.asyncio
async def test_destructive_and_non_idempotent_tools_create_undo_point(srv, create_undo_point):
    @srv.tool(annotations=ANNO_DESTRUCTIVE, tags={"x"})
    def delete_thing() -> str:
        """Delete a thing."""
        return "deleted"

    @srv.tool(annotations=ANNO_MUTATE_NON_IDEMPOTENT, tags={"x"})
    def create_thing() -> str:
        """Create a thing."""
        return "created"

    await _call(srv, "delete_thing")
    create_undo_point.assert_called_once_with("re-mcp", "delete_thing")
    create_undo_point.reset_mock()
    await _call(srv, "create_thing")
    create_undo_point.assert_called_once_with("re-mcp", "create_thing")


@pytest.mark.asyncio
async def test_exempt_tools_create_no_undo_point(srv, create_undo_point):
    assert {"undo", "redo", "analyze_database", "save_database"} <= UNDO_POINT_EXEMPT

    @srv.tool(annotations=ANNO_DESTRUCTIVE, tags={"x"})
    def undo() -> str:
        """Undo."""
        return "undone"

    @srv.tool(annotations=ANNO_MUTATE, tags={"x"})
    def analyze_database() -> str:
        """Analyze."""
        return "analyzed"

    @srv.tool(annotations=ANNO_MUTATE, tags={"x"})
    def save_database() -> str:
        """Save."""
        return "saved"

    for name in ("undo", "analyze_database", "save_database"):
        await _call(srv, name)
    create_undo_point.assert_not_called()


@pytest.mark.asyncio
async def test_named_registration_uses_explicit_tool_name(srv, create_undo_point):
    @srv.tool("explicit_name", annotations=ANNO_MUTATE, tags={"x"})
    def impl() -> str:
        """Explicitly named."""
        return "ok"

    await _call(srv, "explicit_name")
    create_undo_point.assert_called_once_with("re-mcp", "explicit_name")


@pytest.mark.asyncio
async def test_async_mutating_tool_creates_undo_point_via_call_ida(
    srv, create_undo_point, monkeypatch
):
    dispatched: list[str] = []

    async def fake_call_ida(fn, *args, **kwargs):
        dispatched.append(getattr(fn, "__name__", "?"))
        return fn(*args, **kwargs)

    monkeypatch.setattr(ida_helpers, "call_ida", fake_call_ida)

    @srv.tool(annotations=ANNO_MUTATE, tags={"x"})
    async def async_mutate() -> str:
        """Async mutate."""
        return "ok"

    assert await _call(srv, "async_mutate") == "ok"
    create_undo_point.assert_called_once_with("re-mcp", "async_mutate")
    assert dispatched, "undo point must be created through call_ida for async tools"


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_database_open_skips_undo_point(srv, create_undo_point, monkeypatch):
    monkeypatch.setattr(session, "_current_path", None)

    @srv.tool(annotations=ANNO_MUTATE, tags={"x"})
    def mutate() -> str:
        """Mutate."""
        return "ran"

    assert await _call(srv, "mutate") == "ran"
    create_undo_point.assert_not_called()


@pytest.mark.asyncio
async def test_undo_point_failure_does_not_block_tool(srv, create_undo_point, caplog):
    create_undo_point.side_effect = RuntimeError("boom")

    @srv.tool(annotations=ANNO_MUTATE, tags={"x"})
    def mutate() -> str:
        """Mutate."""
        return "ran"

    with caplog.at_level(logging.WARNING, logger="re_mcp_ida.server"):
        assert await _call(srv, "mutate") == "ran"
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "mutate" in warnings[0].getMessage()


@pytest.mark.asyncio
async def test_undo_point_refused_is_logged_at_debug_only(srv, create_undo_point, caplog):
    create_undo_point.return_value = False

    @srv.tool(annotations=ANNO_MUTATE, tags={"x"})
    def mutate() -> str:
        """Mutate."""
        return "ran"

    with caplog.at_level(logging.DEBUG, logger="re_mcp_ida.server"):
        assert await _call(srv, "mutate") == "ran"
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert any(r.levelno == logging.DEBUG and "mutate" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_wrapped_tool_keeps_signature_and_docstring(srv, create_undo_point):
    @srv.tool(annotations=ANNO_MUTATE, tags={"x"})
    def set_thing(address: str, value: int = 3) -> str:
        """Set a thing.

        Longer explanation.
        """
        return f"{address}={value}"

    tool = await srv.get_tool("set_thing")
    assert set(tool.parameters["properties"]) == {"address", "value"}
    assert tool.description.splitlines()[0] == "Set a thing."
    assert await tool.fn(address="a", value=5) == "a=5"


# ---------------------------------------------------------------------------
# undo/redo responses and the removed per-tool points
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("module", ["patching.py", "assemble.py"])
def test_patch_tools_no_longer_create_their_own_point(module):
    source = (_TOOLS_DIR / module).read_text(encoding="utf-8")
    assert "create_undo_point" not in source
    assert "import ida_undo" not in source
    assert "creates an undo point" not in source
