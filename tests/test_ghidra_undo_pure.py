# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Issue #39 — Ghidra ``undo``/``redo`` report the reverted call's label and
the remaining undo/redo steps.

``perform_undo``/``perform_redo`` take the program object directly, so they
run here against a fake that mirrors what ``DomainObject`` does on Ghidra
12.1.2: ``getUndoName()`` is the most recent transaction label (``""`` when
none), ``getAllUndoNames()`` lists most-recent-first, and ``undo()`` moves
the front entry onto the redo list.
"""

from __future__ import annotations

import ast
import pathlib

import pytest
from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.tools.undo import UndoRedoResult, perform_redo, perform_undo

UNDO_PY = (
    pathlib.Path(__file__).resolve().parent.parent
    / "packages/re-mcp-ghidra/src/re_mcp_ghidra/tools/undo.py"
)


class FakeProgram:
    """Undo/redo bookkeeping shaped like ``ghidra.framework.model.DomainObject``."""

    def __init__(
        self,
        undo_names: list[str] | None = None,
        redo_names: list[str] | None = None,
        *,
        raise_on_undo: bool = False,
        raise_on_redo: bool = False,
        blank_names: bool = False,
    ) -> None:
        self.undo_names = list(undo_names or [])
        self.redo_names = list(redo_names or [])
        self.raise_on_undo = raise_on_undo
        self.raise_on_redo = raise_on_redo
        self.blank_names = blank_names

    def canUndo(self) -> bool:
        return bool(self.undo_names)

    def canRedo(self) -> bool:
        return bool(self.redo_names)

    def getUndoName(self) -> str:
        if self.blank_names or not self.undo_names:
            return ""
        return self.undo_names[0]

    def getRedoName(self) -> str:
        if self.blank_names or not self.redo_names:
            return ""
        return self.redo_names[0]

    def getAllUndoNames(self) -> list[str]:
        return list(self.undo_names)

    def getAllRedoNames(self) -> list[str]:
        return list(self.redo_names)

    def undo(self) -> None:
        if self.raise_on_undo:
            raise RuntimeError("Can not undo while transaction is open")
        self.redo_names.insert(0, self.undo_names.pop(0))

    def redo(self) -> None:
        if self.raise_on_redo:
            raise RuntimeError("redo boom")
        self.undo_names.insert(0, self.redo_names.pop(0))


THREE_STEPS = ["Rename function", "Set comment", "Rename function"]


def test_undo_reports_label_and_remaining_counts():
    program = FakeProgram(THREE_STEPS)
    result = perform_undo(program)
    assert isinstance(result, UndoRedoResult)
    assert result.model_dump() == {
        "action": "undo",
        "label": "Rename function",
        "remaining_undo": 2,
        "remaining_redo": 1,
    }


def test_second_undo_reports_next_label():
    program = FakeProgram(THREE_STEPS)
    perform_undo(program)
    result = perform_undo(program)
    assert result.label == "Set comment"
    assert result.remaining_undo == 1
    assert result.remaining_redo == 2


def test_redo_reports_label_and_remaining_counts():
    program = FakeProgram(THREE_STEPS)
    perform_undo(program)
    perform_undo(program)
    result = perform_redo(program)
    assert result.model_dump() == {
        "action": "redo",
        "label": "Set comment",
        "remaining_undo": 2,
        "remaining_redo": 1,
    }


def test_undo_with_empty_history_raises_undo_failed():
    with pytest.raises(GhidraError) as exc_info:
        perform_undo(FakeProgram())
    assert exc_info.value.error_type == "UndoFailed"
    assert "Nothing to undo" in str(exc_info.value)


def test_redo_with_empty_history_raises_redo_failed():
    with pytest.raises(GhidraError) as exc_info:
        perform_redo(FakeProgram(THREE_STEPS))
    assert exc_info.value.error_type == "RedoFailed"
    assert "Nothing to redo" in str(exc_info.value)


def test_undo_exception_is_wrapped_with_original_message():
    program = FakeProgram(THREE_STEPS, raise_on_undo=True)
    with pytest.raises(GhidraError) as exc_info:
        perform_undo(program)
    assert exc_info.value.error_type == "UndoFailed"
    assert "Can not undo while transaction is open" in str(exc_info.value)


def test_redo_exception_is_wrapped_with_original_message():
    program = FakeProgram(["Set comment"], ["Rename function"], raise_on_redo=True)
    with pytest.raises(GhidraError) as exc_info:
        perform_redo(program)
    assert exc_info.value.error_type == "RedoFailed"
    assert "redo boom" in str(exc_info.value)


def test_blank_undo_name_becomes_null_label():
    program = FakeProgram(["Rename function"], blank_names=True)
    result = perform_undo(program)
    assert result.label is None
    assert result.remaining_undo == 0
    assert result.remaining_redo == 1


def test_blank_redo_name_becomes_null_label():
    program = FakeProgram([], ["Rename function"], blank_names=True)
    result = perform_redo(program)
    assert result.label is None
    assert result.remaining_undo == 1
    assert result.remaining_redo == 0


def _tool_bodies() -> dict[str, ast.FunctionDef]:
    tree = ast.parse(UNDO_PY.read_text(encoding="utf-8"), filename=str(UNDO_PY))
    register = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "register")
    return {n.name: n for n in register.body if isinstance(n, ast.FunctionDef)}


def _called_names(fn: ast.FunctionDef) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                names.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                names.add(node.func.attr)
    return names


def test_undo_tool_delegates_to_perform_undo():
    calls = _called_names(_tool_bodies()["undo"])
    assert "perform_undo" in calls
    assert "undo" not in calls, "tool must not call program.undo() itself"


def test_redo_tool_delegates_to_perform_redo():
    calls = _called_names(_tool_bodies()["redo"])
    assert "perform_redo" in calls
    assert "redo" not in calls, "tool must not call program.redo() itself"
