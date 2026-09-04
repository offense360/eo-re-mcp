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


def test_ghidra_does_not_register_undo_redo():
    """Ghidra cannot undo/redo under GhidraProject's batch transaction (#10).

    A tool that can never succeed must not be registered at all: capability
    flags do not affect tool exposure, so an always-failing tool would stay
    visible and invite repeated calls.
    """
    names = _tool_names(GHIDRA_TOOLS_DIR)
    assert names, "no @mcp.tool-decorated functions found — parser regression?"
    assert "undo" not in names
    assert "redo" not in names


def test_ida_still_registers_undo_redo():
    """IDA keeps its undo/redo tools; only the Ghidra backend drops them."""
    names = _tool_names(IDA_TOOLS_DIR)
    assert {"undo", "redo"} <= names
