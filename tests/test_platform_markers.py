# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Regression guard for the ``posix_only`` marker plumbing (issue #16).

The marker must be registered (no ``PytestUnknownMarkWarning``), the skip
condition must track ``sys.platform == "win32"`` exactly, and marked tests
must run unmodified everywhere else.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from tests import conftest


def test_posix_only_marker_is_registered(pytestconfig):
    names = [line.split("(")[0].split(":")[0].strip() for line in pytestconfig.getini("markers")]
    assert "posix_only" in names


def test_is_windows_tracks_sys_platform_only():
    assert conftest.IS_WINDOWS is (sys.platform == "win32")


def _item_with_marks(marks):
    added = []
    item = SimpleNamespace(
        iter_markers=lambda name: [m for m in marks if m.name == name],
        add_marker=added.append,
    )
    return item, added


def test_posix_only_hook_skips_only_on_windows(monkeypatch):
    item, added = _item_with_marks([pytest.mark.posix_only(reason="needs SIGKILL").mark])

    monkeypatch.setattr(conftest, "IS_WINDOWS", False)
    conftest.pytest_collection_modifyitems(None, [item])
    assert added == []

    monkeypatch.setattr(conftest, "IS_WINDOWS", True)
    conftest.pytest_collection_modifyitems(None, [item])
    assert [m.name for m in (a.mark for a in added)] == ["skip"]
    assert added[0].mark.kwargs["reason"] == "needs SIGKILL (issue #16)"


def test_posix_only_hook_ignores_unmarked_items(monkeypatch):
    item, added = _item_with_marks([])
    monkeypatch.setattr(conftest, "IS_WINDOWS", True)
    conftest.pytest_collection_modifyitems(None, [item])
    assert added == []


@pytest.mark.posix_only(reason="self-check: marked tests run only where sys.platform != 'win32'")
def test_posix_only_marked_test_runs_only_on_posix():
    assert sys.platform != "win32"
