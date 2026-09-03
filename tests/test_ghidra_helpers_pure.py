# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Unit tests for Ghidra helpers that can run without pyghidra.

``re_mcp_ghidra.helpers`` only imports Ghidra classes lazily inside
functions, so the module itself is importable in the plain test venv.
The ``transaction()`` context manager is exercised with a fake program
object that records ``startTransaction``/``endTransaction`` calls.
"""

from __future__ import annotations

import pytest
from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import transaction


class FakeProgram:
    """Records transaction calls the way ``ghidra.program.model.listing.Program`` would."""

    def __init__(self) -> None:
        self.next_id = 41
        self.calls: list[tuple] = []

    def startTransaction(self, label):
        self.next_id += 1
        self.calls.append(("start", label, self.next_id))
        return self.next_id

    def endTransaction(self, tx_id, commit):
        self.calls.append(("end", tx_id, commit))


class TestTransaction:
    def test_success_commits_once(self):
        program = FakeProgram()
        with transaction(program, "Rename function"):
            program.calls.append(("mutate",))
        assert program.calls == [
            ("start", "Rename function", 42),
            ("mutate",),
            ("end", 42, True),
        ]

    def test_ghidra_error_propagates_and_still_commits(self):
        program = FakeProgram()
        with pytest.raises(GhidraError, match="nope"), transaction(program, "Set color"):
            raise GhidraError("nope", error_type="NotFound")
        assert program.calls == [("start", "Set color", 42), ("end", 42, True)]

    def test_generic_exception_propagates_and_still_commits(self):
        program = FakeProgram()
        with pytest.raises(RuntimeError, match="java says no"), transaction(program, "Write bytes"):
            raise RuntimeError("java says no")
        assert program.calls == [("start", "Write bytes", 42), ("end", 42, True)]

    def test_never_aborts(self):
        program = FakeProgram()
        for exc in (GhidraError("a", error_type="X"), ValueError("b"), KeyError("c")):
            with pytest.raises(type(exc)), transaction(program, "Anything"):
                raise exc
        ends = [c for c in program.calls if c[0] == "end"]
        assert len(ends) == 3
        assert all(commit is True for _, _, commit in ends)
        assert not any(commit is False for _, _, commit in ends)

    def test_failure_logs_warning_mentioning_issue(self, caplog):
        program = FakeProgram()
        with (
            caplog.at_level("WARNING", logger="re_mcp_ghidra.helpers"),
            pytest.raises(ValueError),
            transaction(program, "Patch bytes"),
        ):
            raise ValueError("boom")
        messages = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert len(messages) == 1
        assert "Patch bytes" in messages[0]
        assert "#11" in messages[0]

    def test_success_logs_nothing(self, caplog):
        program = FakeProgram()
        with (
            caplog.at_level("DEBUG", logger="re_mcp_ghidra.helpers"),
            transaction(program, "Quiet"),
        ):
            pass
        assert not [r for r in caplog.records if r.levelname == "WARNING"]
