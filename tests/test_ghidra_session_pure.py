# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Pure unit tests for re_mcp_ghidra.session.Session.open() — no Ghidra required.

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


class FakeProject:
    """Minimal stand-in for ``ghidra.base.project.GhidraProject``."""

    def __init__(self, open_program_behavior, import_result):
        self._open_program_behavior = open_program_behavior
        self._import_result = import_result
        self.open_program_calls: list[tuple] = []
        self.import_calls: list[object] = []
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
    state: dict = {"project": None, "open_project_calls": []}

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
            raise AssertionError("analyze must not be called in these tests")

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
