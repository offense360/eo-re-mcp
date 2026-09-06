# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Issue #41 — ``disassemble_function`` and ``decompile_function`` are paged.

Default page: 500 instructions / 2000 pseudocode lines, no absolute ceiling.
``page_lines`` and ``disassembly_note`` in ``re_mcp_ida.helpers`` are pure and
run against the ``conftest`` idalib stubs; the AST checks make sure the two
tools build their responses through those helpers and core ``paginate``.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path
from unittest.mock import MagicMock

import ida_nalt
import pytest
from re_mcp_ida import helpers
from re_mcp_ida.helpers import disassembly_note, page_lines

pytestmark = pytest.mark.skipif(
    not isinstance(ida_nalt, MagicMock), reason="real idalib installed; stub-only tests"
)

_FUNCTIONS_PY = (
    Path(__file__).resolve().parents[1] / "packages/re-mcp-ida/src/re_mcp_ida/tools/functions.py"
)

# The ELF curl function measured in #41 has 3,958 pseudocode lines.
_BIG = [f"line {i}" for i in range(3958)]


# ---------------------------------------------------------------------------
# page_lines
# ---------------------------------------------------------------------------


def test_page_lines_default_returns_first_2000_lines_and_points_at_the_rest():
    page = page_lines(_BIG, 0, 2000)

    assert page["text"].count("\n") == 1999
    assert page["text"].startswith("line 0\n")
    assert page["text"].endswith("\nline 1999")
    assert page["line_count"] == 3958
    assert page["start_line"] == 0
    assert page["max_lines"] == 2000
    assert page["has_more"] is True
    assert page["next_line"] == 2000
    assert "start_line=2000" in page["note"]
    assert "0-1999 of 3958" in page["note"]


def test_page_lines_second_page_returns_the_remainder_without_a_note():
    page = page_lines(_BIG, 2000, 2000)

    assert page["text"].count("\n") == 1957
    assert page["text"].startswith("line 2000\n")
    assert page["text"].endswith("\nline 3957")
    assert page["line_count"] == 3958
    assert page["has_more"] is False
    assert page["next_line"] is None
    assert page["note"] is None


def test_page_lines_past_the_end_is_empty_not_an_error():
    page = page_lines(_BIG, 5000, 2000)

    assert page["text"] == ""
    assert page["line_count"] == 3958
    assert page["has_more"] is False
    assert page["next_line"] is None
    assert page["note"] is None


def test_page_lines_single_line_function_is_returned_unchanged():
    page = page_lines(["int main() { return 0; }"], 0, 2000)

    assert page["text"] == "int main() { return 0; }"
    assert page["line_count"] == 1
    assert page["has_more"] is False
    assert page["next_line"] is None
    assert page["note"] is None


def test_page_lines_line_i_of_the_page_is_line_start_plus_i_of_the_whole():
    page = page_lines(_BIG, 1000, 100)
    page_lines_list = page["text"].split("\n")

    assert len(page_lines_list) == 100
    assert page["next_line"] == 1100
    for i, text in enumerate(page_lines_list):
        assert text == _BIG[1000 + i]


# ---------------------------------------------------------------------------
# disassembly_note
# ---------------------------------------------------------------------------


def test_disassembly_note_only_when_there_is_more():
    note = disassembly_note(0, 500, 5800)
    assert note == "Showing instructions 0-499 of 5800; call again with offset=500 for more."

    assert disassembly_note(5500, 300, 5800) is None
    assert disassembly_note(0, 42, 42) is None
    assert disassembly_note(6000, 0, 5800) is None


# ---------------------------------------------------------------------------
# Parameter aliases live in re_mcp_ida.helpers (not core)
# ---------------------------------------------------------------------------


def test_pseudocode_line_aliases_are_exported():
    assert "PseudocodeLine" in helpers.__all__
    assert "PseudocodeLines" in helpers.__all__
    assert "page_lines" in helpers.__all__
    assert "disassembly_note" in helpers.__all__


# ---------------------------------------------------------------------------
# Source checks — the tools build their responses through the helpers
# ---------------------------------------------------------------------------


def _tool_body(name: str) -> ast.FunctionDef:
    tree = ast.parse(_FUNCTIONS_PY.read_text(encoding="utf-8"), filename=str(_FUNCTIONS_PY))
    register = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "register")
    return next(n for n in register.body if isinstance(n, ast.FunctionDef) and n.name == name)


def _calls(fn: ast.FunctionDef, callee: str) -> bool:
    return any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == callee
        for n in ast.walk(fn)
    )


def _params(fn: ast.FunctionDef) -> list[str]:
    return [a.arg for a in fn.args.args]


def test_disassemble_function_paginates_and_takes_offset_limit():
    fn = _tool_body("disassemble_function")

    assert _params(fn) == ["address", "offset", "limit"]
    assert _calls(fn, "paginate")
    assert _calls(fn, "disassembly_note")
    assert "ENTIRE" not in ast.get_docstring(fn)


def test_decompile_function_takes_start_line_max_lines_and_pages_via_helper():
    fn = _tool_body("decompile_function")
    one = _tool_body("_decompile_one")

    assert _params(fn) == ["address", "name", "start_line", "max_lines"]
    assert _params(one) == ["target", "start_line", "max_lines"]
    assert _calls(one, "page_lines")
    assert "get_pseudocode_line_map" in ast.get_docstring(fn)


def test_default_pages_are_500_instructions_and_2000_lines():
    dis = _tool_body("disassemble_function")
    dec = _tool_body("decompile_function")

    dis_defaults = {
        a.arg: d for a, d in zip(dis.args.args[-2:], dis.args.defaults[-2:], strict=True)
    }
    dec_defaults = {
        a.arg: d for a, d in zip(dec.args.args[-2:], dec.args.defaults[-2:], strict=True)
    }

    assert dis_defaults["offset"].value == 0
    assert dis_defaults["limit"].value == 500
    assert dec_defaults["start_line"].value == 0
    assert dec_defaults["max_lines"].value == 2000


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


@pytest.fixture
def functions_mod():
    return importlib.import_module("re_mcp_ida.tools.functions")


def test_disassembly_result_carries_page_fields(functions_mod):
    fields = functions_mod.DisassemblyResult.model_fields

    for name in ("address", "name", "instruction_count", "instructions"):
        assert name in fields  # existing fields kept
    assert "not just this page" in fields["instruction_count"].description
    assert fields["offset"].annotation is int
    assert fields["limit"].annotation is int
    assert fields["has_more"].annotation is bool
    assert "note" in fields

    r = functions_mod.DisassemblyResult(
        address="0x140001030",
        name="inflate",
        instruction_count=5800,
        instructions=[],
        offset=0,
        limit=500,
        has_more=True,
        note="x",
    )
    assert r.has_more is True
    assert (
        functions_mod.DisassemblyResult.model_validate(
            {**r.model_dump(), "has_more": False, "note": None}
        ).note
        is None
    )


def test_decompilation_result_carries_page_fields(functions_mod):
    fields = functions_mod.DecompilationResult.model_fields

    for name in ("address", "name", "pseudocode", "warnings"):
        assert name in fields  # existing fields kept
    assert "whole function" in fields["line_count"].description
    assert fields["line_count"].annotation is int
    assert fields["start_line"].annotation is int
    assert fields["max_lines"].annotation is int
    assert fields["has_more"].annotation is bool
    assert "next_line" in fields
    assert "note" in fields

    r = functions_mod.DecompilationResult(
        address="0x140001030",
        name="inflate",
        pseudocode="",
        line_count=1412,
        start_line=100000,
        max_lines=2000,
        has_more=False,
        next_line=None,
        note=None,
    )
    assert r.pseudocode == ""
    assert r.warnings == []


def test_unpaged_payloads_still_validate_with_derived_defaults(functions_mod):
    """Pre-#41 payloads (no page fields) stay valid: the page covers everything."""
    dec = functions_mod.DecompilationResult.model_validate(
        {"address": "0x401000", "name": "main", "pseudocode": "int main()\n{\n  return 0;\n}"}
    )
    assert dec.line_count == 4
    assert dec.start_line == 0
    assert dec.has_more is False
    assert dec.next_line is None
    assert dec.note is None

    empty = functions_mod.DecompilationResult.model_validate(
        {"address": "0x401000", "name": "main", "pseudocode": ""}
    )
    assert empty.line_count == 0

    dis = functions_mod.DisassemblyResult.model_validate(
        {
            "address": "0x401000",
            "name": "main",
            "instruction_count": 1,
            "instructions": [{"address": "0x401000", "disasm": "ret"}],
        }
    )
    assert dis.offset == 0
    assert dis.limit == 500
    assert dis.has_more is False
    assert dis.note is None
