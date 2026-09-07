# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Pure unit tests for ``re_mcp_ghidra.tools.types`` (no JVM needed).

``set_type`` used to hand a function prototype such as ``"int foo(int a, char *b)"``
straight to the data-type parser, which reported ``Unknown data type: '<the whole
prototype>'`` (#36).  The tool now recognises a prototype at a function entry and
points the caller at ``set_function_type`` before any parsing or mutation.
"""

from __future__ import annotations

import ast
import pathlib

import pytest
from re_mcp_ghidra.tools.types import looks_like_prototype

TYPES_PY = (
    pathlib.Path(__file__).resolve().parent.parent
    / "packages"
    / "re-mcp-ghidra"
    / "src"
    / "re_mcp_ghidra"
    / "tools"
    / "types.py"
)
DOCS_TOOLS_MD = pathlib.Path(__file__).resolve().parent.parent / "docs" / "tools.md"


class TestLooksLikePrototype:
    @pytest.mark.parametrize(
        "text",
        [
            "int foo(int)",
            "int foo(int a, char *b)",
            "void __fastcall handler(void *ctx)",
        ],
    )
    def test_prototypes(self, text: str):
        assert looks_like_prototype(text) is True

    @pytest.mark.parametrize(
        "text",
        [
            "char *",
            "struct foo",
            "int",
            "void (*)(int)",  # function pointer type, no name
            "",
        ],
    )
    def test_plain_types(self, text: str):
        assert looks_like_prototype(text) is False


def _set_type_body() -> ast.FunctionDef:
    tree = ast.parse(TYPES_PY.read_text(encoding="utf-8"), filename=str(TYPES_PY))
    register = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "register")
    return next(n for n in register.body if isinstance(n, ast.FunctionDef) and n.name == "set_type")


def _first_line_of_call(fn: ast.FunctionDef, name: str) -> int:
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            target = node.func
            called = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", "")
            if called == name:
                return node.lineno
    raise AssertionError(f"{name}( not called in set_type")


def _first_with_transaction_line(fn: ast.FunctionDef) -> int:
    for node in ast.walk(fn):
        if isinstance(node, ast.With):
            for item in node.items:
                call = item.context_expr
                if (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Name)
                    and call.func.id == "transaction"
                ):
                    return node.lineno
    raise AssertionError("with transaction(...) not found in set_type")


class TestSetTypeChecksForAPrototypeBeforeParsing:
    def test_function_lookup_and_prototype_check_precede_the_type_parser(self):
        fn = _set_type_body()
        parse_line = _first_line_of_call(fn, "_parse_data_type")
        assert _first_line_of_call(fn, "getFunctionAt") < parse_line
        assert _first_line_of_call(fn, "looks_like_prototype") < parse_line

    def test_the_prototype_raise_happens_before_the_transaction(self):
        fn = _set_type_body()
        tx_line = _first_with_transaction_line(fn)
        raises = [
            n.lineno
            for n in ast.walk(fn)
            if isinstance(n, ast.Raise)
            and n.lineno < tx_line
            and "set_function_type" in ast.unparse(n)
        ]
        assert raises, "no raise mentioning set_function_type before the transaction"

    def test_docstring_points_at_set_function_type(self):
        doc = ast.get_docstring(_set_type_body()) or ""
        assert "set_function_type" in doc

    def test_docs_row_mentions_the_redirect(self):
        row = next(
            line
            for line in DOCS_TOOLS_MD.read_text(encoding="utf-8").splitlines()
            if line.startswith("| `set_type` |")
        )
        assert "set_function_type" in row
