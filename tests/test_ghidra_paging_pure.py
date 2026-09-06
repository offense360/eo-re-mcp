# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Pure tests for #41: paged ``disassemble_function`` / ``decompile_function`` (Ghidra).

``page_lines`` / ``disassembly_note`` are plain helpers, ``cached_decompile``
is exercised with a fake program that only implements the two ids the cache
keys on, and the tool bodies are checked with ``ast`` (same approach as
``test_ghidra_helpers_pure.py``) so no Ghidra is needed.
"""

from __future__ import annotations

import ast
import pathlib

import pytest
from re_mcp_ghidra import helpers as ghidra_helpers
from re_mcp_ghidra.helpers import PseudocodeLine, PseudocodeLines, disassembly_note, page_lines
from re_mcp_ghidra.tools import functions as functions_mod
from re_mcp_ghidra.tools.functions import (
    _DECOMPILE_CACHE,
    _DECOMPILE_CACHE_SIZE,
    DecompilationResult,
    DisassemblyResult,
    cached_decompile,
)

_FUNCTIONS_PY = (
    pathlib.Path(__file__).resolve().parent.parent
    / "packages/re-mcp-ghidra/src/re_mcp_ghidra/tools/functions.py"
)

BIG = [f"line {i}" for i in range(3958)]


# ---------------------------------------------------------------------------
# page_lines / disassembly_note
# ---------------------------------------------------------------------------


class TestPageLines:
    def test_default_page_of_big_function(self):
        page = page_lines(BIG, 0, 2000)
        assert page["text"] == "\n".join(BIG[:2000])
        assert page["text"].count("\n") == 1999
        assert page["line_count"] == 3958
        assert page["start_line"] == 0
        assert page["max_lines"] == 2000
        assert page["has_more"] is True
        assert page["next_line"] == 2000
        assert page["note"] == (
            "Showing lines 0-1999 of 3958; call again with start_line=2000 for more."
        )

    def test_second_page_is_the_remainder(self):
        page = page_lines(BIG, 2000, 2000)
        assert page["text"] == "\n".join(BIG[2000:])
        assert page["text"].count("\n") == 1957
        assert page["line_count"] == 3958
        assert page["has_more"] is False
        assert page["next_line"] is None
        assert page["note"] is None

    def test_start_past_end_is_empty_not_an_error(self):
        page = page_lines(BIG, 5000, 2000)
        assert page["text"] == ""
        assert page["line_count"] == 3958
        assert page["has_more"] is False
        assert page["next_line"] is None
        assert page["note"] is None

    def test_single_line_is_returned_as_is(self):
        page = page_lines(["int f(void) { return 0; }"], 0, 2000)
        assert page["text"] == "int f(void) { return 0; }"
        assert page["line_count"] == 1
        assert page["has_more"] is False
        assert page["next_line"] is None

    def test_page_lines_are_the_global_lines(self):
        page = page_lines(BIG, 1000, 100)
        assert page["text"].split("\n") == BIG[1000:1100]
        assert page["next_line"] == 1100
        assert page["note"] == (
            "Showing lines 1000-1099 of 3958; call again with start_line=1100 for more."
        )

    def test_exact_fit_has_no_more(self):
        page = page_lines(BIG[:2000], 0, 2000)
        assert page["has_more"] is False
        assert page["next_line"] is None

    def test_keys(self):
        assert set(page_lines([], 0, 1)) == {
            "text",
            "line_count",
            "start_line",
            "max_lines",
            "has_more",
            "next_line",
            "note",
        }


class TestDisassemblyNote:
    def test_note_only_when_there_is_more(self):
        assert disassembly_note(0, 500, 5800) == (
            "Showing instructions 0-499 of 5800; call again with offset=500 for more."
        )
        assert disassembly_note(5500, 300, 5800) is None
        assert disassembly_note(0, 12, 12) is None
        assert disassembly_note(0, 0, 0) is None
        assert disassembly_note(6000, 0, 5800) is None


class TestAliases:
    def test_aliases_exported_and_bounded(self):
        assert "PseudocodeLine" in ghidra_helpers.__all__
        assert "PseudocodeLines" in ghidra_helpers.__all__
        assert "page_lines" in ghidra_helpers.__all__
        assert "disassembly_note" in ghidra_helpers.__all__
        line_meta = PseudocodeLine.__metadata__[0]
        lines_meta = PseudocodeLines.__metadata__[0]
        assert any(getattr(m, "ge", None) == 0 for m in line_meta.metadata)
        assert any(getattr(m, "ge", None) == 1 for m in lines_meta.metadata)
        # 1.5: no absolute ceiling
        assert not any(getattr(m, "le", None) is not None for m in lines_meta.metadata)


# ---------------------------------------------------------------------------
# cached_decompile (3.1)
# ---------------------------------------------------------------------------


class FakeProgram:
    def __init__(self, uid: int, mod: int) -> None:
        self.uid = uid
        self.mod = mod

    def getUniqueProgramID(self):
        return self.uid

    def getModificationNumber(self):
        return self.mod


class FakeAddress:
    def __init__(self, offset: int) -> None:
        self.offset = offset

    def getOffset(self):
        return self.offset


class FakeFunction:
    def __init__(self, entry: int) -> None:
        self.entry = FakeAddress(entry)

    def getEntryPoint(self):
        return self.entry


class Counter:
    def __init__(self, text: str = "code") -> None:
        self.calls = 0
        self.text = text

    def __call__(self) -> str:
        self.calls += 1
        return f"{self.text}#{self.calls}"


class TestCachedDecompile:
    def setup_method(self):
        _DECOMPILE_CACHE.clear()

    def teardown_method(self):
        _DECOMPILE_CACHE.clear()

    def test_same_modification_number_decompiles_once(self):
        program = FakeProgram(7, 487725)
        func = FakeFunction(0x113250)
        dec = Counter()
        assert cached_decompile(program, func, dec) == "code#1"
        assert cached_decompile(program, func, dec) == "code#1"
        assert dec.calls == 1

    def test_modification_number_change_decompiles_again(self):
        program = FakeProgram(7, 487725)
        func = FakeFunction(0x113250)
        dec = Counter()
        assert cached_decompile(program, func, dec) == "code#1"
        program.mod = 487726
        assert cached_decompile(program, func, dec) == "code#2"
        assert cached_decompile(program, func, dec) == "code#2"
        assert dec.calls == 2
        assert len(_DECOMPILE_CACHE) == 1

    def test_different_program_ids_are_separate_entries(self):
        func = FakeFunction(0x113250)
        dec = Counter()
        assert cached_decompile(FakeProgram(7, 1), func, dec) == "code#1"
        assert cached_decompile(FakeProgram(8, 1), func, dec) == "code#2"
        assert cached_decompile(FakeProgram(7, 1), func, dec) == "code#1"
        assert cached_decompile(FakeProgram(8, 1), func, dec) == "code#2"
        assert dec.calls == 2
        assert len(_DECOMPILE_CACHE) == 2

    def test_different_functions_are_separate_entries(self):
        program = FakeProgram(7, 1)
        dec = Counter()
        assert cached_decompile(program, FakeFunction(0x10), dec) == "code#1"
        assert cached_decompile(program, FakeFunction(0x20), dec) == "code#2"
        assert cached_decompile(program, FakeFunction(0x10), dec) == "code#1"
        assert dec.calls == 2

    def test_ninth_insert_evicts_the_oldest(self):
        assert _DECOMPILE_CACHE_SIZE == 8
        program = FakeProgram(7, 1)
        dec = Counter()
        for i in range(9):
            cached_decompile(program, FakeFunction(0x1000 + i), dec)
        assert dec.calls == 9
        assert len(_DECOMPILE_CACHE) == 8
        assert (7, 0x1000) not in _DECOMPILE_CACHE
        assert (7, 0x1008) in _DECOMPILE_CACHE
        # the first function was evicted, so it decompiles again
        cached_decompile(program, FakeFunction(0x1000), dec)
        assert dec.calls == 10

    def test_hit_moves_entry_to_most_recent(self):
        program = FakeProgram(7, 1)
        dec = Counter()
        for i in range(8):
            cached_decompile(program, FakeFunction(0x1000 + i), dec)
        cached_decompile(program, FakeFunction(0x1000), dec)  # hit -> most recent
        cached_decompile(program, FakeFunction(0x2000), dec)  # evicts 0x1001, not 0x1000
        assert (7, 0x1000) in _DECOMPILE_CACHE
        assert (7, 0x1001) not in _DECOMPILE_CACHE
        assert dec.calls == 9

    def test_jlong_like_ids_are_normalized_to_int(self):
        class JLong(int):
            pass

        program = FakeProgram(JLong(7), JLong(1))
        func = FakeFunction(0x10)
        dec = Counter()
        cached_decompile(program, func, dec)
        key = next(iter(_DECOMPILE_CACHE))
        assert type(key[0]) is int
        assert type(_DECOMPILE_CACHE[key][0]) is int

    def test_failed_decompile_is_not_cached(self):
        program = FakeProgram(7, 1)
        func = FakeFunction(0x10)

        def boom() -> str:
            raise RuntimeError("decompiler died")

        with pytest.raises(RuntimeError, match="decompiler died"):
            cached_decompile(program, func, boom)
        assert len(_DECOMPILE_CACHE) == 0


# ---------------------------------------------------------------------------
# Tool signatures / bodies / models (2)
# ---------------------------------------------------------------------------


def _tool(name: str) -> ast.FunctionDef:
    tree = ast.parse(_FUNCTIONS_PY.read_text(encoding="utf-8"), filename=str(_FUNCTIONS_PY))
    register = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "register")
    return next(n for n in register.body if isinstance(n, ast.FunctionDef) and n.name == name)


def _calls(fn: ast.FunctionDef, name: str) -> bool:
    return any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == name
        for n in ast.walk(fn)
    )


def _param_names(fn: ast.FunctionDef) -> list[str]:
    return [a.arg for a in fn.args.args]


def _default_of(fn: ast.FunctionDef, param: str) -> object:
    args = fn.args.args
    defaults = fn.args.defaults
    pos = [a.arg for a in args].index(param)
    d = defaults[pos - (len(args) - len(defaults))]
    assert isinstance(d, ast.Constant)
    return d.value


class TestToolSources:
    def test_disassemble_function_signature_and_paginate(self):
        fn = _tool("disassemble_function")
        assert _param_names(fn) == ["address", "offset", "limit"]
        assert _default_of(fn, "offset") == 0
        assert _default_of(fn, "limit") == 500
        assert _calls(fn, "paginate")
        assert _calls(fn, "disassembly_note")
        doc = ast.get_docstring(fn) or ""
        assert "ENTIRE" not in doc
        assert "default 500" in doc
        assert "instruction_count" in doc

    def test_decompile_function_signature_and_page_lines(self):
        fn = _tool("decompile_function")
        assert _param_names(fn) == ["address", "start_line", "max_lines"]
        assert _default_of(fn, "start_line") == 0
        assert _default_of(fn, "max_lines") == 2000
        assert _calls(fn, "page_lines")
        assert _calls(fn, "cached_decompile")
        assert _calls(fn, "normalize_pseudocode")
        doc = ast.get_docstring(fn) or ""
        assert "default 2000" in doc
        assert "line_count" in doc

    def test_export_all_pseudocode_does_not_use_the_cache(self):
        export_py = _FUNCTIONS_PY.parent / "export.py"
        assert "cached_decompile" not in export_py.read_text(encoding="utf-8")

    def test_module_exposes_cache_objects(self):
        assert isinstance(functions_mod._DECOMPILE_CACHE, dict)


class TestModels:
    def test_disassembly_result_fields(self):
        fields = DisassemblyResult.model_fields
        for name in ("function_name", "start", "end", "instruction_count", "instructions"):
            assert name in fields
        for name in ("offset", "limit", "has_more", "note"):
            assert name in fields
        assert "not just this page" in (fields["instruction_count"].description or "")
        assert fields["note"].default is None
        r = DisassemblyResult(
            function_name="f",
            start="0x1",
            end="0x2",
            instruction_count=3,
            instructions=[],
            offset=0,
            limit=500,
            has_more=False,
        )
        assert r.note is None

    def test_decompilation_result_fields(self):
        fields = DecompilationResult.model_fields
        for name in ("function_name", "address", "decompiled_code"):
            assert name in fields
        for name in ("line_count", "start_line", "max_lines", "has_more", "next_line", "note"):
            assert name in fields
        assert "whole function" in (fields["line_count"].description or "")
        assert "page" in (fields["decompiled_code"].description or "")
        r = DecompilationResult(
            function_name="f",
            address="0x1",
            decompiled_code="",
            line_count=0,
            start_line=0,
            max_lines=2000,
            has_more=False,
        )
        assert r.next_line is None
        assert r.note is None
