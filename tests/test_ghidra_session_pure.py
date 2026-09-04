# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Pure unit tests for re_mcp_ghidra.session.Session — no Ghidra required.

The lazily imported ``pyghidra`` / ``ghidra.*`` / ``java.*`` modules are stubbed
via ``sys.modules`` inside a fixture so no other test file is affected.

The stubs mirror the pyghidra 3.x project API the session now uses
(``open_project`` / ``consume_program`` / ``program_loader``) rather than
``ghidra.base.project.GhidraProject`` (#18).  Crucially, no long-lived
"Batch Processing" transaction exists in this model, so save goes through
``DomainFile.save`` and the first save mirrors what ``GhidraProject.saveAs``
did by hand.  The ``pyghidra`` stub deliberately has **no** ``analyze``:
auto-analysis is run inline by ``Session.analyze()`` inside one
``helpers.transaction`` (see ``test_analyze_*``), so any call to
``pyghidra.analyze`` fails here with ``AttributeError``.
"""

from __future__ import annotations

import pathlib
import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest
from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.session import Session


class FakeProgramTypeError(TypeError):
    """Stand-in for ``pyghidra.ProgramTypeError``."""


class FakeDomainFile:
    """Stand-in for ``ghidra.framework.model.DomainFile``."""

    def __init__(self, can_save: bool, calls: list | None = None):
        self.can_save = can_save
        self.save_calls: list[object] = []
        self.deleted = False
        self._calls = calls if calls is not None else []

    def canSave(self):
        return self.can_save

    def isBusy(self):
        return False

    def save(self, monitor):
        self.save_calls.append(monitor)
        self._calls.append(("df.save",))
        self.can_save = True

    def delete(self):
        self.deleted = True
        self._calls.append(("df.delete",))


class FakeProgram:
    """Program as returned by the pyghidra loader: no standing transaction."""

    def __init__(self, name="sample.bin", can_save=False, calls: list | None = None):
        self._name = name
        self._calls = calls if calls is not None else []
        self.domain_file = FakeDomainFile(can_save, self._calls)
        self.start_transaction_calls: list[str] = []
        self.end_transaction_calls: list[tuple] = []
        self.release_calls: list[object] = []
        self.clear_undo_calls: list[int] = []
        self.changed = True

    def getName(self):
        return self._name

    def getDomainFile(self):
        return self.domain_file

    def getCurrentTransactionInfo(self):
        return None

    def startTransaction(self, label):
        self.start_transaction_calls.append(label)
        self._calls.append(("start", label))
        return 99

    def endTransaction(self, tx_id, commit):
        self.end_transaction_calls.append((tx_id, commit))
        self._calls.append(("end", tx_id, commit))

    def release(self, consumer):
        self.release_calls.append(consumer)
        self._calls.append(("release", consumer))

    def clearUndo(self):
        """``DomainObject.clearUndo()`` (Ghidra 12.1.2 ``DomainObject.java:569``)."""
        self.clear_undo_calls.append(len(self._calls))
        self._calls.append(("clearUndo",))

    def isChanged(self):
        return self.changed

    def isLocked(self):
        return False


class FakeFolder:
    """Stand-in for ``ghidra.framework.model.DomainFolder`` (project root)."""

    def __init__(self, calls: list, existing: FakeDomainFile | None = None):
        self._calls = calls
        self._existing = existing
        self.get_file_calls: list[str] = []
        self.create_file_calls: list[tuple] = []

    def getFile(self, name):
        self.get_file_calls.append(name)
        return self._existing

    def createFile(self, name, obj, monitor):
        self.create_file_calls.append((name, obj, monitor))
        self._calls.append(("createFile", name))
        df = obj.getDomainFile()
        if df is not None:
            df.can_save = True
        obj.changed = False
        return df


class FakeProjectData:
    def __init__(self, folder):
        self._folder = folder

    def getRootFolder(self):
        return self._folder


class FakeProject:
    """Minimal stand-in for a ``ghidra.framework.model.Project``."""

    def __init__(self, calls: list, existing_file: FakeDomainFile | None = None):
        self._calls = calls
        self.folder = FakeFolder(calls, existing_file)
        self.project_data = FakeProjectData(self.folder)
        self.closed = False

    def getProjectData(self):
        return self.project_data

    def close(self):
        self.closed = True
        self._calls.append(("project.close",))


class FakeLoadResults:
    """Stand-in for ``ghidra.app.util.opinion.LoadResults`` (AutoCloseable)."""

    def __init__(self, program, calls: list):
        self._program = program
        self._calls = calls
        self.consumers: list[object] = []
        self.closed = False

    def getPrimaryDomainObject(self, consumer):
        self.consumers.append(consumer)
        self._calls.append(("getPrimaryDomainObject", consumer))
        return self._program

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True
        self._calls.append(("loadResults.close",))
        return False


class FakeBuilder:
    """Stand-in for ``ProgramLoader.Builder`` — records the chained config."""

    def __init__(self, state: dict):
        self._state = state
        self.config: dict = {}

    def _set(self, key, value):
        self.config[key] = value
        self._state["builder_config"] = self.config
        return self

    def project(self, p):
        return self._set("project", p)

    def source(self, f):
        return self._set("source", f)

    def name(self, n):
        return self._set("name", n)

    def monitor(self, m):
        return self._set("monitor", m)

    def language(self, lang):
        return self._set("language", lang)

    def compiler(self, cspec):
        return self._set("compiler", cspec)

    def load(self):
        self._state["calls"].append(("load",))
        error = self._state["load_error"]
        if error is not None:
            raise error
        return FakeLoadResults(self._state["import_result"], self._state["calls"])


def _make_module(name: str, **attrs) -> ModuleType:
    mod = ModuleType(name)
    for k, v in attrs.items():
        setattr(mod, k, v)
    return mod


@pytest.fixture
def ghidra_stubs(monkeypatch):
    """Install ``pyghidra``/``ghidra``/``java`` stubs for the duration of a test.

    Returns a dict the test uses to configure the fakes.
    """
    state: dict = {
        "project": None,
        "open_project_calls": [],
        # What consume_program does: a FakeProgram/MagicMock to return, an
        # exception instance to raise, or None (treated as "not there").
        "consume_result": None,
        "consume_calls": [],
        # What program_loader().…​.load() yields.
        "import_result": None,
        "load_error": None,
        "builder_config": None,
        # GhidraProgramUtilities stub: what isAnalyzed() reports, an
        # exception the fake AutoAnalysisManager.startAnalysis should raise,
        # and an ordered call log.
        "is_analyzed": False,
        "analysis_error": None,
        "calls": [],
    }

    def open_project(path, name, create=False):
        state["open_project_calls"].append((str(path), name, create))
        state["calls"].append(("open_project", str(path), name, create))
        return state["project"]

    def consume_program(project, path, consumer=None):
        state["consume_calls"].append((project, path, consumer))
        state["calls"].append(("consume_program", path, consumer))
        result = state["consume_result"]
        if isinstance(result, BaseException):
            raise result
        return (result, consumer) if result is not None else (None, consumer)

    def program_loader():
        return FakeBuilder(state)

    # No ``analyze`` on purpose: the session must not call pyghidra.analyze()
    # (it re-serialises the analysis log on every callback, #18).
    pyghidra_stub = _make_module(
        "pyghidra",
        open_project=open_project,
        consume_program=consume_program,
        program_loader=program_loader,
        ProgramTypeError=FakeProgramTypeError,
    )

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

    class AutoAnalysisManager:
        """Records the calls ``GhidraProject.analyze`` made (Ghidra 12.1.2)."""

        @staticmethod
        def getAnalysisManager(program):
            state["calls"].append(("getAnalysisManager", program))
            mgr = MagicMock(name="AutoAnalysisManager")
            mgr.initializeOptions.side_effect = lambda: state["calls"].append(
                ("initializeOptions", program)
            )
            mgr.reAnalyzeAll.side_effect = lambda restrict: state["calls"].append(
                ("reAnalyzeAll", program, restrict)
            )

            def start_analysis(monitor):
                state["calls"].append(("startAnalysis", program, monitor))
                if state["analysis_error"] is not None:
                    raise state["analysis_error"]

            mgr.startAnalysis.side_effect = start_analysis
            return mgr

        @staticmethod
        def getLanguageService():
            return state.get("language_service") or MagicMock(name="LanguageService")

    class JavaObject:
        """Stand-in for ``java.lang.Object`` used as the session consumer."""

    modules = {
        "pyghidra": pyghidra_stub,
        "ghidra": _make_module("ghidra"),
        "ghidra.app": _make_module("ghidra.app"),
        "ghidra.app.plugin": _make_module("ghidra.app.plugin"),
        "ghidra.app.plugin.core": _make_module("ghidra.app.plugin.core"),
        "ghidra.app.plugin.core.analysis": _make_module(
            "ghidra.app.plugin.core.analysis", AutoAnalysisManager=AutoAnalysisManager
        ),
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
        "java.io": _make_module("java.io", File=File),
        "java.lang": _make_module("java.lang", Object=JavaObject),
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


# ---------------------------------------------------------------------------
# open() — existing project / re-import (#9)
# ---------------------------------------------------------------------------


def test_reopen_empty_project_reimports(ghidra_stubs, existing_project):
    """#9: the project exists but holds no program → import through the loader."""
    program = MagicMock(name="program")
    project = FakeProject(ghidra_stubs["calls"])
    ghidra_stubs["project"] = project
    ghidra_stubs["consume_result"] = FileNotFoundError("no program")
    ghidra_stubs["import_result"] = program

    session, result = _open(existing_project)

    assert result["status"] == "ok"
    assert ("load",) in ghidra_stubs["calls"]
    assert ghidra_stubs["builder_config"]["source"].path == str(existing_project.resolve())
    assert ghidra_stubs["builder_config"]["project"] is project
    assert session.is_open()
    assert session.program is program
    assert not project.closed


def test_reopen_missing_program_none_still_reimports(ghidra_stubs, existing_project):
    program = MagicMock(name="program")
    project = FakeProject(ghidra_stubs["calls"])
    ghidra_stubs["project"] = project
    ghidra_stubs["consume_result"] = None
    ghidra_stubs["import_result"] = program

    session, result = _open(existing_project)

    assert result["status"] == "ok"
    assert ("load",) in ghidra_stubs["calls"]
    assert session.program is program


def test_reopen_other_exception_closes_project_and_raises(ghidra_stubs, existing_project):
    project = FakeProject(ghidra_stubs["calls"])
    ghidra_stubs["project"] = project
    ghidra_stubs["consume_result"] = RuntimeError("corrupt")
    ghidra_stubs["import_result"] = MagicMock(name="program")

    with pytest.raises(GhidraError) as excinfo:
        _open(existing_project)

    assert excinfo.value.error_type == "RuntimeError"
    assert ("load",) not in ghidra_stubs["calls"]
    assert project.closed


def test_reopen_non_program_file_raises_import_failed(ghidra_stubs, existing_project):
    """``pyghidra.ProgramTypeError`` → ImportFailed, project closed."""
    project = FakeProject(ghidra_stubs["calls"])
    ghidra_stubs["project"] = project
    ghidra_stubs["consume_result"] = FakeProgramTypeError("not a Program")

    with pytest.raises(GhidraError) as excinfo:
        _open(existing_project)

    assert excinfo.value.error_type == "ImportFailed"
    assert project.closed


def test_reimport_failure_closes_project(ghidra_stubs, existing_project):
    project = FakeProject(ghidra_stubs["calls"])
    ghidra_stubs["project"] = project
    ghidra_stubs["consume_result"] = FileNotFoundError("no program")
    ghidra_stubs["import_result"] = None

    with pytest.raises(GhidraError) as excinfo:
        _open(existing_project)

    assert excinfo.value.error_type == "ImportFailed"
    assert ("load",) in ghidra_stubs["calls"]
    assert project.closed


def test_load_exception_closes_project(ghidra_stubs, existing_project):
    project = FakeProject(ghidra_stubs["calls"])
    ghidra_stubs["project"] = project
    ghidra_stubs["consume_result"] = FileNotFoundError("no program")
    ghidra_stubs["load_error"] = RuntimeError("LoadException: no loader")

    with pytest.raises(GhidraError) as excinfo:
        _open(existing_project)

    assert excinfo.value.error_type == "ImportFailed"
    assert project.closed


def test_open_existing_uses_consume_program_with_session_consumer(ghidra_stubs, existing_project):
    """The session owns the consumer it later releases in close()."""
    program = FakeProgram(can_save=True, calls=ghidra_stubs["calls"])
    ghidra_stubs["project"] = FakeProject(ghidra_stubs["calls"])
    ghidra_stubs["consume_result"] = program

    session, _ = _open(existing_project)

    assert len(ghidra_stubs["consume_calls"]) == 1
    _project, path, consumer = ghidra_stubs["consume_calls"][0]
    assert path == "/sample.bin"
    assert consumer is not None

    session.close(save=False)

    assert program.release_calls == [consumer]


def test_open_project_created_only_when_project_file_absent(ghidra_stubs, tmp_path):
    """A fresh directory → ``open_project(..., create=True)``."""
    binary = tmp_path / "fresh.bin"
    binary.write_bytes(b"\x00" * 16)
    program = MagicMock(name="program")
    ghidra_stubs["project"] = FakeProject(ghidra_stubs["calls"])
    ghidra_stubs["import_result"] = program

    session, result = _open(binary)

    assert result["status"] == "ok"
    assert ghidra_stubs["open_project_calls"][0][1] == "fresh.bin"
    assert ghidra_stubs["open_project_calls"][0][2] is True
    # Nothing to consume: a brand-new project goes straight to the loader.
    assert ghidra_stubs["consume_calls"] == []
    assert session.program is program


def test_open_existing_project_does_not_create(ghidra_stubs, existing_project):
    ghidra_stubs["project"] = FakeProject(ghidra_stubs["calls"])
    ghidra_stubs["consume_result"] = MagicMock(name="program")

    _open(existing_project)

    assert ghidra_stubs["open_project_calls"][0][2] is False


def test_import_names_program_after_the_binary(ghidra_stubs, existing_project):
    """The reopen path looks the program up as ``/<binary name>``."""
    ghidra_stubs["project"] = FakeProject(ghidra_stubs["calls"])
    ghidra_stubs["consume_result"] = FileNotFoundError("no program")
    ghidra_stubs["import_result"] = MagicMock(name="program")

    _open(existing_project)

    assert ghidra_stubs["builder_config"]["name"] == "sample.bin"


def test_import_initializes_analysis_options_in_a_transaction(ghidra_stubs, existing_project):
    """``GhidraProject.initializeProgram`` did this; the loader does not."""
    program = FakeProgram(calls=ghidra_stubs["calls"])
    ghidra_stubs["project"] = FakeProject(ghidra_stubs["calls"])
    ghidra_stubs["consume_result"] = FileNotFoundError("no program")
    ghidra_stubs["import_result"] = program

    _open(existing_project)

    calls = ghidra_stubs["calls"]
    names = [c[0] for c in calls]
    assert "initializeOptions" in names
    start = names.index("start")
    init = names.index("initializeOptions")
    end = names.index("end")
    assert start < init < end
    assert program.end_transaction_calls == [(99, True)]


# ---------------------------------------------------------------------------
# save() / close(save=True) — issue #1 under the new API
# ---------------------------------------------------------------------------


def _open_existing(ghidra_stubs, existing_project, program, existing_file=None):
    """Reopen an existing project whose program is *program* (the S6 / #9-B path)."""
    project = FakeProject(ghidra_stubs["calls"], existing_file)
    ghidra_stubs["project"] = project
    ghidra_stubs["consume_result"] = program
    session, _ = _open(existing_project)
    return session, project


def test_save_uses_domain_file_save_when_file_can_save(ghidra_stubs, existing_project):
    """No standing transaction → ``DomainFile.save`` is allowed directly (#1)."""
    program = FakeProgram(can_save=True, calls=ghidra_stubs["calls"])
    session, project = _open_existing(ghidra_stubs, existing_project, program)

    session.save()

    assert len(program.domain_file.save_calls) == 1
    assert project.folder.create_file_calls == []


def test_second_save_uses_domain_file_save(ghidra_stubs, existing_project):
    program = FakeProgram(can_save=False, calls=ghidra_stubs["calls"])
    session, project = _open_existing(ghidra_stubs, existing_project, program)

    session.save()
    session.save()

    assert len(project.folder.create_file_calls) == 1
    assert len(program.domain_file.save_calls) == 1


def test_first_save_creates_file_then_second_save_saves(ghidra_stubs, existing_project):
    """First save has no project file (``canSave()`` false) → createFile."""
    program = FakeProgram(can_save=False, calls=ghidra_stubs["calls"])
    session, project = _open_existing(ghidra_stubs, existing_project, program)

    session.save()
    assert project.folder.create_file_calls[0][0] == "sample.bin"
    assert project.folder.create_file_calls[0][1] is program
    assert program.domain_file.save_calls == []

    session.save()
    assert len(program.domain_file.save_calls) == 1
    assert len(project.folder.create_file_calls) == 1


def test_first_save_deletes_existing_then_creates(ghidra_stubs, existing_project):
    """Mirrors ``GhidraProject.saveAs(..., overWrite=True)``: delete then create."""
    program = FakeProgram(can_save=False, calls=ghidra_stubs["calls"])
    stale = FakeDomainFile(can_save=True, calls=ghidra_stubs["calls"])
    session, project = _open_existing(ghidra_stubs, existing_project, program, existing_file=stale)

    session.save()

    assert stale.deleted
    assert project.folder.get_file_calls == ["sample.bin"]
    assert project.folder.create_file_calls[0][0] == "sample.bin"
    order = [c[0] for c in ghidra_stubs["calls"] if c[0] in ("df.delete", "createFile")]
    assert order == ["df.delete", "createFile"]


def test_save_does_not_touch_transactions(ghidra_stubs, existing_project):
    """Saving must neither open nor close a transaction of its own."""
    program = FakeProgram(can_save=True, calls=ghidra_stubs["calls"])
    session, _ = _open_existing(ghidra_stubs, existing_project, program)
    program.start_transaction_calls.clear()
    program.end_transaction_calls.clear()

    session.save()

    assert program.start_transaction_calls == []
    assert program.end_transaction_calls == []


def test_close_with_save_saves_then_closes(ghidra_stubs, existing_project):
    program = FakeProgram(can_save=True, calls=ghidra_stubs["calls"])
    session, project = _open_existing(ghidra_stubs, existing_project, program)

    result = session.close(save=True)

    assert result["status"] == "closed"
    assert len(program.domain_file.save_calls) == 1
    assert project.closed
    assert not session.is_open()


def test_close_releases_program_before_project_close(ghidra_stubs, existing_project):
    """``DefaultProjectData.close()`` defers dispose while a consumer holds the
    program, which leaves a stale ``.lock`` behind; release must come first."""
    program = FakeProgram(can_save=True, calls=ghidra_stubs["calls"])
    session, _project = _open_existing(ghidra_stubs, existing_project, program)
    ghidra_stubs["calls"].clear()

    session.close(save=True)

    names = [c[0] for c in ghidra_stubs["calls"]]
    assert "release" in names
    assert "project.close" in names
    assert names.index("release") < names.index("project.close")
    assert program.release_calls  # released with the session's consumer


def test_close_without_save_still_releases_and_closes(ghidra_stubs, existing_project):
    program = FakeProgram(can_save=True, calls=ghidra_stubs["calls"])
    session, project = _open_existing(ghidra_stubs, existing_project, program)

    session.close(save=False)

    assert program.domain_file.save_calls == []
    assert program.release_calls
    assert project.closed


def test_close_save_failure_raises_close_failed(ghidra_stubs, existing_project):
    program = FakeProgram(can_save=True, calls=ghidra_stubs["calls"])
    session, _project = _open_existing(ghidra_stubs, existing_project, program)

    def boom(monitor):
        raise RuntimeError("Unable to lock due to active transaction")

    program.domain_file.save = boom

    with pytest.raises(GhidraError) as excinfo:
        session.close(save=True)

    assert excinfo.value.error_type == "CloseFailed"
    assert not session.is_open()


# ---------------------------------------------------------------------------
# analyzed flag reporting — issue #8
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("flag", [True, False])
def test_open_existing_program_reports_isAnalyzed(ghidra_stubs, existing_project, flag):
    program = MagicMock(name="program")
    ghidra_stubs["project"] = FakeProject(ghidra_stubs["calls"])
    ghidra_stubs["consume_result"] = program
    ghidra_stubs["is_analyzed"] = flag

    _, result = _open(existing_project)

    assert result.get("analyzed") is flag
    assert ("isAnalyzed", program) in ghidra_stubs["calls"]


def test_open_import_reports_not_analyzed(ghidra_stubs, existing_project):
    """A (re)imported program is never analyzed, whatever isAnalyzed would say."""
    program = MagicMock(name="program")
    ghidra_stubs["project"] = FakeProject(ghidra_stubs["calls"])
    ghidra_stubs["consume_result"] = FileNotFoundError("no program")
    ghidra_stubs["import_result"] = program
    ghidra_stubs["is_analyzed"] = True

    _, result = _open(existing_project)

    assert result.get("analyzed") is False
    assert ("isAnalyzed", program) not in ghidra_stubs["calls"]


def test_open_with_run_auto_analysis_uses_inline_analysis(ghidra_stubs, existing_project):
    """run_auto_analysis=True: resetAnalysisFlags → inline analysis → mark.

    The ``pyghidra`` stub has no ``analyze`` (calling it raises
    AttributeError), and Ghidra 12.1.2 has no ``setAnalyzedFlag``, so this
    only passes when the session runs the analysis itself inside one
    ``helpers.transaction`` (#18).
    """
    program = FakeProgram(calls=ghidra_stubs["calls"])
    ghidra_stubs["project"] = FakeProject(ghidra_stubs["calls"])
    ghidra_stubs["consume_result"] = program

    session = Session()
    result = session.open(str(existing_project), run_auto_analysis=True)

    names = [c[0] for c in ghidra_stubs["calls"]]
    assert "analyze" not in names
    assert names.index("reset") < names.index("start")
    assert names[names.index("start") : names.index("end") + 1] == [
        "start",
        "getAnalysisManager",
        "initializeOptions",
        "reAnalyzeAll",
        "startAnalysis",
        "end",
    ]
    assert program.start_transaction_calls == ["Analyze"]
    assert program.end_transaction_calls == [(99, True)]
    assert names.index("end") < names.index("mark")
    assert ("mark", program) in ghidra_stubs["calls"]
    assert result.get("analyzed") is True


def test_mark_program_analyzed_calls_utility(ghidra_stubs, existing_project):
    program = MagicMock(name="program")
    session, _ = _open_existing(ghidra_stubs, existing_project, program)
    assert hasattr(session, "mark_program_analyzed")

    session.mark_program_analyzed()

    assert ghidra_stubs["calls"][-1] == ("mark", program)


# ---------------------------------------------------------------------------
# capabilities — issue #10 / #18
# ---------------------------------------------------------------------------


def test_capabilities_report_undo_available(ghidra_stubs, existing_project):
    """With no standing transaction ``canUndo()`` works, so undo is offered (#18).

    Under ``GhidraProject`` a "Batch Processing" transaction stayed open for
    the life of the program and Ghidra only allows undo/redo when no
    transaction is active, which is why the capability used to be False (#10).
    """
    program = FakeProgram(calls=ghidra_stubs["calls"])
    ghidra_stubs["project"] = FakeProject(ghidra_stubs["calls"])
    ghidra_stubs["consume_result"] = program

    session, _ = _open(existing_project)

    assert "undo" in session.capabilities
    assert session.capabilities["undo"] is True


def test_no_ghidra_project_import(ghidra_stubs, existing_project):
    """The session must not fall back to ``ghidra.base.project.GhidraProject``."""
    program = FakeProgram(calls=ghidra_stubs["calls"])
    ghidra_stubs["project"] = FakeProject(ghidra_stubs["calls"])
    ghidra_stubs["consume_result"] = program

    _open(existing_project)

    assert "ghidra.base.project" not in sys.modules


# ---------------------------------------------------------------------------
# analyze() and the undo history — issue #18
# ---------------------------------------------------------------------------


def _analysis_names(calls) -> list[str]:
    keep = {
        "start",
        "getAnalysisManager",
        "initializeOptions",
        "reAnalyzeAll",
        "startAnalysis",
        "end",
        "mark",
        "clearUndo",
    }
    return [c[0] for c in calls if c[0] in keep]


def test_analyze_runs_in_one_transaction_then_marks_and_clears_undo(ghidra_stubs, existing_project):
    """Same calls as ``GhidraProject.analyze`` (Ghidra 12.1.2), in one transaction.

    ``markProgramAnalyzed`` opens its own transaction, so it runs after the
    "Analyze" one is committed; the undo history is cleared last because an
    analysis pass is not an undo step (matches IDA).
    """
    program = FakeProgram(calls=ghidra_stubs["calls"])
    session, _ = _open_existing(ghidra_stubs, existing_project, program)
    ghidra_stubs["calls"].clear()

    session.analyze()

    assert _analysis_names(ghidra_stubs["calls"]) == [
        "start",
        "getAnalysisManager",
        "initializeOptions",
        "reAnalyzeAll",
        "startAnalysis",
        "end",
        "mark",
        "clearUndo",
    ]
    assert program.start_transaction_calls == ["Analyze"]
    assert program.end_transaction_calls == [(99, True)]
    reanalyze = next(c for c in ghidra_stubs["calls"] if c[0] == "reAnalyzeAll")
    assert reanalyze == ("reAnalyzeAll", program, None)
    start_analysis = next(c for c in ghidra_stubs["calls"] if c[0] == "startAnalysis")
    assert start_analysis[2] is sys.modules["ghidra.util.task"].TaskMonitor.DUMMY
    assert ghidra_stubs["calls"].count(("mark", program)) == 1


def test_analyze_without_mark_skips_mark_but_clears_undo(ghidra_stubs, existing_project):
    """``reanalyze_range`` must not flip the persisted analyzed flag (#8)."""
    program = FakeProgram(calls=ghidra_stubs["calls"])
    session, _ = _open_existing(ghidra_stubs, existing_project, program)
    ghidra_stubs["calls"].clear()

    session.analyze(mark_analyzed=False)

    names = _analysis_names(ghidra_stubs["calls"])
    assert "mark" not in names
    assert names[-1] == "clearUndo"
    assert program.end_transaction_calls == [(99, True)]


def test_analyze_failure_aborts_transaction_and_raises(ghidra_stubs, existing_project):
    """A failing pass is rolled back like any other tool transaction."""
    program = FakeProgram(calls=ghidra_stubs["calls"])
    session, _ = _open_existing(ghidra_stubs, existing_project, program)
    ghidra_stubs["calls"].clear()
    ghidra_stubs["analysis_error"] = RuntimeError("analyzer exploded")

    with pytest.raises(RuntimeError, match="analyzer exploded"):
        session.analyze()

    assert program.end_transaction_calls == [(99, False)]
    names = _analysis_names(ghidra_stubs["calls"])
    assert "mark" not in names
    assert "clearUndo" not in names


def test_analyze_without_open_database_raises(ghidra_stubs):
    session = Session()

    with pytest.raises(GhidraError) as excinfo:
        session.analyze()

    assert excinfo.value.error_type == "NoDatabase"


def test_open_clears_undo_history_last_on_import(ghidra_stubs, existing_project):
    """The loader and "Initialize analysis options" leave undo entries (#18 U5);
    ``open()`` clears them once everything else is done."""
    program = FakeProgram(calls=ghidra_stubs["calls"])
    ghidra_stubs["project"] = FakeProject(ghidra_stubs["calls"])
    ghidra_stubs["consume_result"] = FileNotFoundError("no program")
    ghidra_stubs["import_result"] = program

    _open(existing_project)

    assert ghidra_stubs["calls"][-1] == ("clearUndo",)
    assert len(program.clear_undo_calls) == 1


def test_open_clears_undo_history_last_on_existing_project(ghidra_stubs, existing_project):
    program = FakeProgram(can_save=True, calls=ghidra_stubs["calls"])
    _open_existing(ghidra_stubs, existing_project, program)

    assert ghidra_stubs["calls"][-1] == ("clearUndo",)
    assert len(program.clear_undo_calls) == 1


def test_open_with_run_auto_analysis_clears_undo_once_at_the_end(ghidra_stubs, existing_project):
    """The ``run_auto_analysis`` pass is not an undo step either, and the
    history is cleared exactly once, after ``markProgramAnalyzed``."""
    program = FakeProgram(calls=ghidra_stubs["calls"])
    ghidra_stubs["project"] = FakeProject(ghidra_stubs["calls"])
    ghidra_stubs["consume_result"] = program

    Session().open(str(existing_project), run_auto_analysis=True)

    assert ghidra_stubs["calls"][-1] == ("clearUndo",)
    assert len(program.clear_undo_calls) == 1
    names = [c[0] for c in ghidra_stubs["calls"]]
    assert names.index("mark") < names.index("clearUndo")


def test_no_pyghidra_analyze_reference():
    """``pyghidra.analyze`` must not be called anywhere in the Ghidra package.

    It accumulates the analysis log quadratically on every callback and we
    discard the result (~20 % slower in the #18 spike); ``Session.analyze``
    runs the same four ``AutoAnalysisManager`` calls inline instead.
    """
    src_dir = (
        pathlib.Path(__file__).resolve().parent.parent
        / "packages"
        / "re-mcp-ghidra"
        / "src"
        / "re_mcp_ghidra"
    )
    offenders = [
        str(path.relative_to(src_dir))
        for path in sorted(src_dir.rglob("*.py"))
        if "pyghidra.analyze(" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []
