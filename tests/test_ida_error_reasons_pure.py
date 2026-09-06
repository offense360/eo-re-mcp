# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Issue #33 — rename and comment failures say *why*.

``ida_name.set_name(..., SN_CHECK)`` returns a bare ``False`` for an invalid
identifier and silently *moves* an existing name on a conflict; ``idc.set_cmt``
returns ``False`` for an unmapped address.  ``check_new_name`` and
``check_mapped`` run before those calls and raise an ``IDAError`` that names
the reason.  Runs without idalib: ``ida_name`` / ``ida_bytes`` /
``ida_idaapi`` are ``MagicMock`` stubs from ``conftest``.
"""

from __future__ import annotations

import re
from pathlib import Path

import ida_bytes
import ida_idaapi
import ida_name
import pytest
from re_mcp_ida import helpers
from re_mcp_ida.helpers import IDAError

_TOOLS_DIR = Path(__file__).resolve().parents[1] / "packages/re-mcp-ida/src/re_mcp_ida/tools"

_BADADDR = 0xFFFFFFFFFFFFFFFF
_EA = 0x140001010
_OTHER = 0x1400049F0


@pytest.fixture
def name_stub(monkeypatch):
    """Configure the ``ida_name`` / ``ida_idaapi`` stubs for one test."""
    if not hasattr(ida_name.set_name, "return_value"):  # real idalib present
        pytest.skip("real idalib installed; stub-only test")
    monkeypatch.setattr(ida_idaapi, "BADADDR", _BADADDR, raising=False)
    monkeypatch.setattr(ida_name.is_ident, "return_value", True)
    monkeypatch.setattr(ida_name.validate_name, "side_effect", lambda name, *a, **k: name)
    monkeypatch.setattr(ida_name.get_name_ea, "return_value", _BADADDR)
    return monkeypatch


def test_invalid_identifier_names_reason_and_suggestion(name_stub):
    name_stub.setattr(ida_name.is_ident, "return_value", False)
    name_stub.setattr(
        ida_name.validate_name, "side_effect", lambda name, *a, **k: "bad_name_with_spaces_"
    )

    with pytest.raises(IDAError) as ei:
        helpers.check_new_name(_EA, "bad name with spaces!", what="function name")

    assert ei.value.error_type == "InvalidName"
    msg = ei.value.args[0]
    assert "'bad name with spaces!'" in msg
    assert "'bad_name_with_spaces_'" in msg
    assert "function name" in msg


def test_name_conflict_names_other_address(name_stub):
    name_stub.setattr(ida_name.get_name_ea, "return_value", _OTHER)

    with pytest.raises(IDAError) as ei:
        helpers.check_new_name(_EA, "entry", what="function name")

    assert ei.value.error_type == "NameConflict"
    msg = ei.value.args[0]
    assert "'entry'" in msg
    assert "0x1400049F0" in msg
    assert "already used" in msg


def test_same_address_is_not_a_conflict(name_stub):
    name_stub.setattr(ida_name.get_name_ea, "return_value", _EA)

    assert helpers.check_new_name(_EA, "entry") is None


def test_empty_name_rejected(name_stub):
    with pytest.raises(IDAError) as ei:
        helpers.check_new_name(_EA, "", what="function name")

    assert ei.value.error_type == "InvalidName"
    assert "must not be empty" in ei.value.args[0]


def test_valid_unused_name_passes(name_stub):
    assert helpers.check_new_name(_EA, "ok_name_33") is None


def test_unmapped_address_rejected(monkeypatch):
    if not hasattr(ida_bytes.is_mapped, "return_value"):  # real idalib present
        pytest.skip("real idalib installed; stub-only test")
    monkeypatch.setattr(ida_bytes.is_mapped, "return_value", False)

    with pytest.raises(IDAError) as ei:
        helpers.check_mapped(0x1, purpose="set a comment")

    assert ei.value.error_type == "InvalidAddress"
    msg = ei.value.args[0]
    assert "0x1" in msg
    assert "not in any segment" in msg
    assert "set a comment" in msg


def test_mapped_address_passes(monkeypatch):
    if not hasattr(ida_bytes.is_mapped, "return_value"):  # real idalib present
        pytest.skip("real idalib installed; stub-only test")
    monkeypatch.setattr(ida_bytes.is_mapped, "return_value", True)

    assert helpers.check_mapped(_EA, purpose="set a comment") is None


# ---------------------------------------------------------------------------
# Source checks: the guards run *before* the IDA call in every tool that
# reaches set_name / set_cmt.
# ---------------------------------------------------------------------------


def _guard_precedes_every_call(module: str, guard: str, call: str) -> None:
    source = (_TOOLS_DIR / module).read_text(encoding="utf-8")
    calls = [m.start() for m in re.finditer(re.escape(call), source)]
    assert calls, f"{module}: no {call} found"
    for pos in calls:
        preceding = source[:pos]
        assert guard in preceding, f"{module}: {call} at offset {pos} is not preceded by {guard}"
        # The nearest guard must belong to the same tool body: no ``def `` in between.
        last_guard = preceding.rfind(guard)
        assert "    def " not in source[last_guard:pos], (
            f"{module}: {call} at offset {pos} has no {guard} in the same tool"
        )


@pytest.mark.parametrize("module", ["functions.py", "names.py"])
def test_rename_tools_check_name_before_set_name(module):
    _guard_precedes_every_call(module, "check_new_name(", "ida_name.set_name(")


def test_comment_tools_check_mapping_before_set_cmt():
    _guard_precedes_every_call("comments.py", "check_mapped(", "idc.set_cmt(")
