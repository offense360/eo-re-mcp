# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Undo and redo operations."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import ANNO_DESTRUCTIVE
from re_mcp_ghidra.session import session


class UndoRedoResult(BaseModel):
    """Result of an undo/redo operation."""

    action: str = Field(description="Action performed: 'undo' or 'redo'.")
    label: str | None = Field(
        default=None,
        description=(
            "Transaction label of the tool call that was undone/redone "
            "(e.g. 'Rename function'); null when Ghidra reports none."
        ),
    )
    remaining_undo: int = Field(description="Undo steps still available after this call.")
    remaining_redo: int = Field(description="Redo steps still available after this call.")


def _label(name: object) -> str | None:
    """Turn a Java/Python undo name into ``str | None`` (``""`` → ``None``)."""
    return str(name or "") or None


def perform_undo(program) -> UndoRedoResult:
    """Undo one transaction on *program* and report label and remaining steps.

    The label is read before ``undo()`` because Ghidra's ``getUndoName()``
    names the step that the *next* undo would revert.  The tool never opens
    a transaction of its own: Ghidra refuses to undo while one is open.
    """
    if not program.canUndo():
        raise GhidraError("Nothing to undo", error_type="UndoFailed")
    label = _label(program.getUndoName())
    try:
        program.undo()
    except Exception as e:
        raise GhidraError(f"Undo failed: {e}", error_type="UndoFailed") from e
    return UndoRedoResult(
        action="undo",
        label=label,
        remaining_undo=len(program.getAllUndoNames()),
        remaining_redo=len(program.getAllRedoNames()),
    )


def perform_redo(program) -> UndoRedoResult:
    """Redo one transaction on *program* and report label and remaining steps."""
    if not program.canRedo():
        raise GhidraError("Nothing to redo", error_type="RedoFailed")
    label = _label(program.getRedoName())
    try:
        program.redo()
    except Exception as e:
        raise GhidraError(f"Redo failed: {e}", error_type="RedoFailed") from e
    return UndoRedoResult(
        action="redo",
        label=label,
        remaining_undo=len(program.getAllUndoNames()),
        remaining_redo=len(program.getAllRedoNames()),
    )


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"utility"})
    @session.require_open
    def undo() -> UndoRedoResult:
        """Undo the last database modification.

        Returns the label of the reverted tool call and how many undo/redo
        steps remain; each mutating tool call is one step, failed calls
        leave none.  Ghidra keeps at most 50 undo steps.
        """
        return perform_undo(session.program)

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"utility"})
    @session.require_open
    def redo() -> UndoRedoResult:
        """Redo the last undone database modification.

        Returns the label of the re-applied tool call and how many undo/redo
        steps remain; each mutating tool call is one step, failed calls
        leave none.  Ghidra keeps at most 50 undo steps.
        """
        return perform_redo(session.program)
