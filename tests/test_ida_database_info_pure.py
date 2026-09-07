# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Issue #38 (IDA half) — ``get_database_info`` reports the shared core set.

Both backends now return ``entry_point``, ``image_base``, ``endian``,
``compiler_spec`` and ``capabilities`` (plus their own extras).  On IDA the
new values come from ``ida_nalt.get_imagebase()``, ``ida_ida.inf_is_be()``,
``ida_typeinf.get_compiler_name(ida_ida.inf_get_cc_id())`` and the session's
probed capabilities.  Schema and AST checks only; runs on the ``conftest``
idalib stubs.
"""

from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock

import ida_nalt
import pytest
from re_mcp_ida.tools.database import DatabaseInfoResult

pytestmark = pytest.mark.skipif(
    not isinstance(ida_nalt, MagicMock), reason="real idalib installed; stub-only tests"
)

_DATABASE_PY = (
    Path(__file__).resolve().parents[1] / "packages/re-mcp-ida/src/re_mcp_ida/tools/database.py"
)

EXPECTED_DESCRIPTIONS = {
    "image_base": "Image base address (hex)",
    "endian": "'little' or 'big'",
    "compiler_spec": (
        "Compiler identification: IDA's compiler name (e.g. 'Visual C++'), "
        "Ghidra's compiler spec id (e.g. 'windows')"
    ),
    "capabilities": "Available capabilities: decompiler, assembler, undo",
}


def test_new_fields_are_required_and_documented():
    fields = DatabaseInfoResult.model_fields
    for name, description in EXPECTED_DESCRIPTIONS.items():
        assert name in fields, name
        assert fields[name].is_required(), name
        assert fields[name].description == description, name
    assert fields["capabilities"].annotation == dict[str, bool]


def test_new_fields_follow_entry_point_and_keep_the_old_order():
    names = list(DatabaseInfoResult.model_fields)
    assert names == [
        "file_path",
        "processor",
        "bitness",
        "file_type",
        "min_address",
        "max_address",
        "entry_point",
        "image_base",
        "endian",
        "compiler_spec",
        "capabilities",
        "function_count",
        "segment_count",
        "entry_point_count",
        "trusted",
    ]


def test_tool_body_uses_the_documented_ida_calls():
    tree = ast.parse(_DATABASE_PY.read_text(encoding="utf-8"))
    tool = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "get_database_info"
    )
    src = ast.unparse(tool)
    assert "ida_nalt.get_imagebase(" in src
    assert "ida_ida.inf_is_be(" in src
    assert "ida_typeinf.get_compiler_name(" in src
    assert "ida_ida.inf_get_cc_id(" in src
    assert "session.capabilities" in src
