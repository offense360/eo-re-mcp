# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Pure tests for the Ghidra tool catalog — no Ghidra required.

Tool modules are scanned with ``ast`` (same approach as
``test_tool_brief_budget.py``) so nothing under ``re_mcp_ghidra.tools`` is
imported.
"""

from __future__ import annotations

import ast
import pathlib

PACKAGES = pathlib.Path(__file__).resolve().parent.parent / "packages"
GHIDRA_TOOLS_DIR = PACKAGES / "re-mcp-ghidra" / "src" / "re_mcp_ghidra" / "tools"
IDA_TOOLS_DIR = PACKAGES / "re-mcp-ida" / "src" / "re_mcp_ida" / "tools"


def _is_mcp_tool_decorated(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if (
            isinstance(target, ast.Attribute)
            and target.attr == "tool"
            and isinstance(target.value, ast.Name)
            and target.value.id == "mcp"
        ):
            return True
    return False


def _tool_names(tools_dir: pathlib.Path) -> set[str]:
    """Return the names of every ``@mcp.tool``-decorated function under *tools_dir*."""
    names: set[str] = set()
    for path in sorted(tools_dir.glob("*.py")):
        if path.name.startswith("_"):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_mcp_tool_decorated(
                node
            ):
                names.add(node.name)
    return names


def test_ghidra_registers_undo_redo():
    """Ghidra can undo/redo again once no standing transaction is held (#18).

    The tools were removed in #10 because ``GhidraProject``'s batch transaction
    made ``canUndo()`` permanently false, and a tool that can never succeed
    must not be registered at all. With the pyghidra project API each tool
    transaction is one undo step, so the tools are back.
    """
    names = _tool_names(GHIDRA_TOOLS_DIR)
    assert names, "no @mcp.tool-decorated functions found — parser regression?"
    assert "undo" in names
    assert "redo" in names


def test_ida_still_registers_undo_redo():
    """IDA keeps its undo/redo tools; only the Ghidra backend drops them."""
    names = _tool_names(IDA_TOOLS_DIR)
    assert {"undo", "redo"} <= names
