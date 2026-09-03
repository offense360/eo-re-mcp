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
