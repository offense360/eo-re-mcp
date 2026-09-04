# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Pure unit tests for re_mcp_ida.session.Session — no idalib required.

Relies on the IDA module stubs installed by ``conftest.py``.
"""

from __future__ import annotations

import ida_auto
import idapro
import pytest
from re_mcp_ida.session import Session


@pytest.fixture
def idalib_stub(monkeypatch):
    """Make ``idapro.open_database`` succeed and ``ida_auto.auto_is_ok`` configurable."""
    if not hasattr(idapro.open_database, "return_value"):  # real idalib present
        pytest.skip("real idalib installed; stub-only test")
    monkeypatch.setattr(idapro.open_database, "return_value", 0)
    return monkeypatch


@pytest.mark.parametrize(
    ("sidecar", "auto_ok", "expected"),
    [
        (True, True, True),
        (True, False, False),
        (False, True, False),
    ],
)
def test_open_reports_analyzed_from_sidecar_and_auto_is_ok(
    idalib_stub, tmp_path, sidecar, auto_ok, expected
):
    """``analyzed`` is true only when a stored .i64 exists *and* IDA reports
    auto-analysis as finished (#8)."""
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x00" * 16)
    if sidecar:
        (tmp_path / "sample.bin.i64").write_bytes(b"IDA2")
    idalib_stub.setattr(ida_auto.auto_is_ok, "return_value", auto_ok)

    result = Session().open(str(binary))

    assert result.get("analyzed") is expected


# --- #23: close() must leave the auto-analysis queue intact -----------------


@pytest.fixture
def open_session(idalib_stub, tmp_path):
    """An open ``Session`` on a fresh binary with all ``ida_auto`` call records cleared."""
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x00" * 16)
    # Real ida_auto exposes AU_* queue-type constants; the MagicMock stub only
    # lists what has been set on it, so give it a few (values from auto.hpp).
    for name, value in (("AU_NONE", 0), ("AU_UNK", 10), ("AU_CODE", 20), ("AU_PROC", 30)):
        idalib_stub.setattr(ida_auto, name, value, raising=False)
    sess = Session()
    sess.open(str(binary))
    ida_auto.reset_mock()
    idapro.close_database.reset_mock()
    return sess


def test_close_keeps_auto_queue(open_session):
    """Closing with save must not drain the queue: a saved-but-unanalyzed .i64
    has to keep reporting ``auto_is_ok()==False`` on reopen (#23)."""
    open_session.close(save=True)

    assert ida_auto.auto_unmark.call_count == 0
    idapro.close_database.assert_called_once_with(True)
    ida_auto.enable_auto.assert_called_once_with(False)


def test_close_without_save_keeps_auto_queue(open_session):
    open_session.close(save=False)

    assert ida_auto.auto_unmark.call_count == 0
    idapro.close_database.assert_called_once_with(False)
