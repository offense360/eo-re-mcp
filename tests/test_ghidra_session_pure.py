# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Pure unit tests for re_mcp_ghidra.session.Session — no Ghidra required.

The lazily imported ``ghidra.*`` / ``java.io`` modules are stubbed via
``sys.modules`` inside a fixture so no other test file is affected.
"""

from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest
from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.session import Session


class FakeFileNotFoundException(Exception):
    """Stand-in for ``java.io.FileNotFoundException`` as exposed by jpype."""


class FakeTransactionInfo:
    """Stand-in for the ``TransactionInfo`` GhidraProject keeps open per program."""

    def __init__(self, tx_id=7, description="Batch Processing"):
        self._id = tx_id
        self._description = description

    def getID(self):
        return self._id

    def getStatus(self):
        return "NOT_DONE"

    def getDescription(self):
        return self._description

    def getOpenSubTransactions(self):
        return [self._description]


class FakeDomainFile:
    """Stand-in for ``ghidra.framework.model.DomainFile``."""

    def __init__(self, can_save: bool):
        self.can_save = can_save
        self.save_calls: list[object] = []

    def canSave(self):
        return self.can_save

    def isBusy(self):
        return True

    def save(self, monitor):
        self.save_calls.append(monitor)


class FakeProgram:
    """Program as returned by GhidraProject: its batch transaction is always open.

    ``endTransaction`` mimics Ghidra: ``TransactionInfo.getID()`` is the DB handle
    transaction id, not an entry id, so ending it that way always fails.
    """

    def __init__(self, name="sample.bin", can_save=False):
        self._name = name
        self.domain_file = FakeDomainFile(can_save)
        self.tx = FakeTransactionInfo()
        self.end_transaction_calls: list[tuple] = []
        self.changed = True

    def getName(self):
        return self._name

    def getDomainFile(self):
        return self.domain_file

    def getCurrentTransactionInfo(self):
        return self.tx

    def endTransaction(self, tx_id, commit):
        self.end_transaction_calls.append((tx_id, commit))
        raise RuntimeError("java.lang.IllegalStateException: Transaction not found")

    def isChanged(self):
        return self.changed

    def isLocked(self):
        return False


class FakeProject:
    """Minimal stand-in for ``ghidra.base.project.GhidraProject``."""

    def __init__(self, open_program_behavior, import_result, save_error=None):
        self._open_program_behavior = open_program_behavior
        self._import_result = import_result
        self._save_error = save_error
        self.open_program_calls: list[tuple] = []
        self.import_calls: list[object] = []
        self.save_calls: list[object] = []
        self.save_as_calls: list[tuple] = []
        self.closed = False

    def openProgram(self, folder, name, read_only):
        self.open_program_calls.append((folder, name, read_only))
        behavior = self._open_program_behavior
        if isinstance(behavior, BaseException):
            raise behavior
        return behavior

    def importProgram(self, file):
        self.import_calls.append(file)
        return self._import_result

    def save(self, program):
        self.save_calls.append(program)
        if self._save_error is not None:
            raise self._save_error
        program.domain_file.can_save = True
        program.changed = False

    def saveAs(self, program, folder, name, overwrite):
        self.save_as_calls.append((program, folder, name, overwrite))
        program.domain_file.can_save = True
        program.changed = False

    def close(self):
        self.closed = True


def _make_module(name: str, **attrs) -> ModuleType:
    mod = ModuleType(name)
    for k, v in attrs.items():
        setattr(mod, k, v)
    return mod


@pytest.fixture
def ghidra_stubs(monkeypatch):
    """Install ``ghidra``/``java`` stubs into sys.modules for the duration of a test.

    Returns a dict the test uses to configure the fake project.
    """
    state: dict = {
        "project": None,
        "open_project_calls": [],
        # GhidraProgramUtilities stub: what isAnalyzed() reports, whether
        # GhidraProject.analyze() may be called, and an ordered call log.
        "is_analyzed": False,
        "allow_analyze": False,
        "calls": [],
    }

    class GhidraProject:
        @staticmethod
        def openProject(location, name):
            state["open_project_calls"].append((location, name))
            return state["project"]

        @staticmethod
        def createProject(location, name, temporary):
            raise AssertionError("createProject must not be called for an existing project")

        @staticmethod
        def analyze(program):
            if not state["allow_analyze"]:
                raise AssertionError("analyze must not be called in these tests")
            state["calls"].append(("analyze", program))

    class GhidraProgramUtilities:
        """Only the members that exist in Ghidra 12.1.2 — no setAnalyzedFlag."""

        @staticmethod
        def isAnalyzed(program):
            state["calls"].append(("isAnalyzed", program))
            return state["is_analyzed"]

        @staticmethod
        def markProgramAnalyzed(program):
            state["calls"].append(("mark", program))

        @staticmethod
        def resetAnalysisFlags(program):
            state["calls"].append(("reset", program))

    class TaskMonitor:
        DUMMY = object()

    def FlatProgramAPI(program, monitor):
        return MagicMock(name="FlatProgramAPI")

    class File:
        def __init__(self, path):
            self.path = path

    modules = {
        "ghidra": _make_module("ghidra"),
        "ghidra.base": _make_module("ghidra.base"),
        "ghidra.base.project": _make_module("ghidra.base.project", GhidraProject=GhidraProject),
        "ghidra.program": _make_module("ghidra.program"),
        "ghidra.program.flatapi": _make_module(
            "ghidra.program.flatapi", FlatProgramAPI=FlatProgramAPI
        ),
        "ghidra.program.model": _make_module("ghidra.program.model"),
        "ghidra.program.model.lang": _make_module(
            "ghidra.program.model.lang", CompilerSpecID=MagicMock(), LanguageID=MagicMock()
        ),
        "ghidra.program.util": _make_module(
            "ghidra.program.util", GhidraProgramUtilities=GhidraProgramUtilities
        ),
        "ghidra.util": _make_module("ghidra.util"),
        "ghidra.util.task": _make_module("ghidra.util.task", TaskMonitor=TaskMonitor),
        "java": _make_module("java"),
        "java.io": _make_module(
            "java.io", File=File, FileNotFoundException=FakeFileNotFoundException
        ),
    }
    for name, mod in modules.items():
        monkeypatch.setitem(sys.modules, name, mod)
    return state


@pytest.fixture
def existing_project(tmp_path):
    """Create a dummy binary plus an existing (empty) project file next to it."""
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x00" * 16)
    project_dir = tmp_path / "ghidra_projects"
    project_dir.mkdir()
    (project_dir / "sample.bin.gpr").write_text("")
    return binary


def _open(binary):
    session = Session()
    return session, session.open(str(binary))


def test_reopen_empty_project_reimports(ghidra_stubs, existing_project):
    program = MagicMock(name="program")
    project = FakeProject(FakeFileNotFoundException("no program"), program)
    ghidra_stubs["project"] = project

    session, result = _open(existing_project)

    assert result["status"] == "ok"
    assert len(project.import_calls) == 1
    assert project.import_calls[0].path == str(existing_project.resolve())
    assert session.is_open()
    assert session.program is program
    assert not project.closed


def test_reopen_missing_program_none_still_reimports(ghidra_stubs, existing_project):
    program = MagicMock(name="program")
    project = FakeProject(None, program)
    ghidra_stubs["project"] = project

    session, result = _open(existing_project)

    assert result["status"] == "ok"
    assert len(project.import_calls) == 1
    assert session.program is program


def test_reopen_other_exception_closes_project_and_raises(ghidra_stubs, existing_project):
    project = FakeProject(RuntimeError("corrupt"), MagicMock(name="program"))
    ghidra_stubs["project"] = project

    with pytest.raises(GhidraError) as excinfo:
        _open(existing_project)

    assert excinfo.value.error_type == "RuntimeError"
    assert project.import_calls == []
    assert project.closed


def test_reimport_failure_closes_project(ghidra_stubs, existing_project):
    project = FakeProject(FakeFileNotFoundException("no program"), None)
    ghidra_stubs["project"] = project

    with pytest.raises(GhidraError) as excinfo:
        _open(existing_project)

    assert excinfo.value.error_type == "ImportFailed"
    assert len(project.import_calls) == 1
    assert project.closed


# ---------------------------------------------------------------------------
# save() / close(save=True) — issue #1
# ---------------------------------------------------------------------------


def _open_existing(ghidra_stubs, existing_project, program, **project_kwargs):
    """Reopen an existing project whose program is *program* (the S6 / #9-B path)."""
    project = FakeProject(program, None, **project_kwargs)
    ghidra_stubs["project"] = project
    session, _ = _open(existing_project)
    return session, project


def test_save_uses_project_save_when_file_can_save(ghidra_stubs, existing_project):
    program = FakeProgram(can_save=True)
    session, project = _open_existing(ghidra_stubs, existing_project, program)

    session.save()

    assert project.save_calls == [program]
    assert program.domain_file.save_calls == []
    assert project.save_as_calls == []


def test_first_save_uses_save_as_then_project_save(ghidra_stubs, existing_project):
    program = FakeProgram(can_save=False)
    session, project = _open_existing(ghidra_stubs, existing_project, program)

    session.save()
    assert project.save_as_calls == [(program, "/", "sample.bin", True)]
    assert project.save_calls == []

    session.save()
    assert project.save_calls == [program]
    assert len(project.save_as_calls) == 1
    assert program.domain_file.save_calls == []


def test_save_does_not_end_ghidra_project_transaction(ghidra_stubs, existing_project):
    program = FakeProgram(can_save=True)
    session, _ = _open_existing(ghidra_stubs, existing_project, program)

    session.save()

    assert program.end_transaction_calls == []


def test_close_with_save_saves_via_project_then_closes(ghidra_stubs, existing_project):
    program = FakeProgram(can_save=True)
    session, project = _open_existing(ghidra_stubs, existing_project, program)

    result = session.close(save=True)

    assert result["status"] == "closed"
    assert project.save_calls == [program]
    assert program.domain_file.save_calls == []
    assert project.closed
    assert not session.is_open()


def test_close_save_failure_raises_close_failed(ghidra_stubs, existing_project):
    program = FakeProgram(can_save=True)
    session, project = _open_existing(
        ghidra_stubs,
        existing_project,
        program,
        save_error=RuntimeError("Unable to lock due to active transaction"),
    )

    with pytest.raises(GhidraError) as excinfo:
        session.close(save=True)

    assert excinfo.value.error_type == "CloseFailed"
    assert project.save_calls == [program]
    assert not session.is_open()


# ---------------------------------------------------------------------------
# analyzed flag reporting — issue #8
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("flag", [True, False])
def test_open_existing_program_reports_isAnalyzed(ghidra_stubs, existing_project, flag):
    program = MagicMock(name="program")
    ghidra_stubs["project"] = FakeProject(program, None)
    ghidra_stubs["is_analyzed"] = flag

    _, result = _open(existing_project)

    assert result.get("analyzed") is flag
    assert ("isAnalyzed", program) in ghidra_stubs["calls"]


def test_open_import_reports_not_analyzed(ghidra_stubs, existing_project):
    """A (re)imported program is never analyzed, whatever isAnalyzed would say."""
    program = MagicMock(name="program")
    ghidra_stubs["project"] = FakeProject(FakeFileNotFoundException("no program"), program)
    ghidra_stubs["is_analyzed"] = True

    _, result = _open(existing_project)

    assert result.get("analyzed") is False
    assert ("isAnalyzed", program) not in ghidra_stubs["calls"]


def test_open_with_run_auto_analysis_resets_then_marks(ghidra_stubs, existing_project):
    """run_auto_analysis=True: resetAnalysisFlags → analyze → markProgramAnalyzed.

    Ghidra 12.1.2 has no ``setAnalyzedFlag``; the stub deliberately omits it so
    the old call fails here.
    """
    program = MagicMock(name="program")
    ghidra_stubs["project"] = FakeProject(program, None)
    ghidra_stubs["allow_analyze"] = True

    session = Session()
    result = session.open(str(existing_project), run_auto_analysis=True)

    ordered = [c for c in ghidra_stubs["calls"] if c[0] in ("reset", "analyze", "mark")]
    assert ordered == [("reset", program), ("analyze", program), ("mark", program)]
    assert result.get("analyzed") is True


def test_mark_program_analyzed_calls_utility(ghidra_stubs, existing_project):
    program = MagicMock(name="program")
    session, _ = _open_existing(ghidra_stubs, existing_project, program)
    assert hasattr(session, "mark_program_analyzed")

    session.mark_program_analyzed()

    assert ghidra_stubs["calls"][-1] == ("mark", program)
