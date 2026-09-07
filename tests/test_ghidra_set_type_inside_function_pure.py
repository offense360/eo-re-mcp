# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Pure unit tests for the ``set_type`` inside-a-function guard (#49, no JVM needed).

``set_type(address, "int")`` at a function entry or anywhere inside a function
body used to answer ``status: ok`` while silently replacing the instructions
there with data.  The tool now refuses such addresses unless ``force=True`` and
tells the caller about ``set_function_type``, ``delete_function`` and ``force``.
"""

from __future__ import annotations

import ast
import pathlib

import pytest
from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.tools.types import refuse_set_type_inside_function

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


class _FakeAddress:
    def __init__(self, offset: int) -> None:
        self._offset = offset

    def getOffset(self) -> int:
        return self._offset


class _FakeFunction:
    def __init__(self, name: str, entry: int) -> None:
        self._name = name
        self._entry = _FakeAddress(entry)

    def getName(self) -> str:
        return self._name

    def getEntryPoint(self) -> _FakeAddress:
        return self._entry


class _FakeFunctionManager:
    def __init__(self, containing: _FakeFunction | None) -> None:
        self._containing = containing
        self.queried: list[_FakeAddress] = []

    def getFunctionContaining(self, addr: _FakeAddress) -> _FakeFunction | None:
        self.queried.append(addr)
        return self._containing


class _FakeProgram:
    def __init__(self, containing: _FakeFunction | None) -> None:
        self.function_manager = _FakeFunctionManager(containing)

    def getFunctionManager(self) -> _FakeFunctionManager:
        return self.function_manager


class TestRefuseSetTypeInsideFunction:
    def test_inside_a_function_without_force_raises_invalid_argument(self):
        program = _FakeProgram(_FakeFunction("FUN_0010fa00", 0x10FA00))
        addr = _FakeAddress(0x10FA68)

        with pytest.raises(GhidraError) as info:
            refuse_set_type_inside_function(program, addr, force=False)

        assert info.value.error_type == "InvalidArgument"
        message = str(info.value)
        assert "FUN_0010fa00" in message
        assert "0x10FA68" in message
        assert "0x10FA00" in message
        assert "set_function_type" in message
        assert "delete_function" in message
        assert "force=True" in message
        assert program.function_manager.queried == [addr]

    def test_inside_a_function_with_force_passes(self):
        program = _FakeProgram(_FakeFunction("FUN_140007cc4", 0x140007CC4))

        assert (
            refuse_set_type_inside_function(program, _FakeAddress(0x140007CC4), force=True) is None
        )

    def test_outside_any_function_passes(self):
        program = _FakeProgram(None)

        assert (
            refuse_set_type_inside_function(program, _FakeAddress(0x140099000), force=False) is None
        )


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


class TestSetTypeCallsTheGuardBetweenThePrototypeCheckAndTheParser:
    def test_call_order(self):
        fn = _set_type_body()
        prototype_line = _first_line_of_call(fn, "looks_like_prototype")
        guard_line = _first_line_of_call(fn, "refuse_set_type_inside_function")
        parse_line = _first_line_of_call(fn, "_parse_data_type")
        tx_line = _first_with_transaction_line(fn)
        assert prototype_line < guard_line < parse_line < tx_line

    def test_guard_receives_the_force_argument(self):
        fn = _set_type_body()
        call = next(
            n
            for n in ast.walk(fn)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == "refuse_set_type_inside_function"
        )
        assert "force" in ast.unparse(call)

    def test_force_parameter_defaults_to_false(self):
        fn = _set_type_body()
        names = [a.arg for a in fn.args.args]
        assert "force" in names
        defaults = dict(zip(names[-len(fn.args.defaults) :], fn.args.defaults, strict=True))
        assert isinstance(defaults["force"], ast.Constant)
        assert defaults["force"].value is False

    def test_docstring_describes_force(self):
        doc = ast.get_docstring(_set_type_body()) or ""
        assert "force" in doc
        assert "delete_function" in doc

    def test_docs_row_mentions_the_force_flag(self):
        row = next(
            line
            for line in DOCS_TOOLS_MD.read_text(encoding="utf-8").splitlines()
            if line.startswith("| `set_type` |")
        )
        assert "force=True" in row
        assert "inside a function" in row
