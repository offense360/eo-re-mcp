# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Pure unit tests for the Hex-Rays tools adopted from upstream PR #48 (issue #6).

Relies on the IDA module stubs installed by ``conftest.py``; the module-level
helpers under test are exercised against ``MagicMock`` IDA modules, so no
idalib is required.
"""

from __future__ import annotations

import importlib
from types import SimpleNamespace
from unittest.mock import MagicMock

import ida_bytes
import ida_frame
import ida_hexrays
import ida_nalt
import ida_typeinf
import pytest
from re_mcp_ida.helpers import IDAError

pytestmark = pytest.mark.skipif(
    not isinstance(ida_nalt, MagicMock), reason="real idalib installed; stub-only tests"
)

FUNC_START = 0x140001010
CALL_EA = 0x14000108B


# ---------------------------------------------------------------------------
# set_call_type / clear_call_type (tools/function_type.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def function_type_mod():
    ida_nalt.set_op_tinfo.reset_mock()
    ida_nalt.get_op_tinfo.reset_mock()
    ida_nalt.del_op_tinfo.reset_mock()
    ida_hexrays.mark_cfunc_dirty.reset_mock()
    ida_typeinf.apply_callee_tinfo.reset_mock()
    return importlib.import_module("re_mcp_ida.tools.function_type")


def test_apply_call_site_type_sets_operand_type_then_marks_dirty(function_type_mod):
    ida_nalt.set_op_tinfo.return_value = True
    tif = object()

    function_type_mod.apply_call_site_type(CALL_EA, tif, FUNC_START)

    ida_nalt.set_op_tinfo.assert_called_once_with(CALL_EA, 0, tif)
    ida_hexrays.mark_cfunc_dirty.assert_called_once_with(FUNC_START, False)
    ida_typeinf.apply_callee_tinfo.assert_not_called()


def test_apply_call_site_type_raises_when_set_op_tinfo_fails(function_type_mod):
    ida_nalt.set_op_tinfo.return_value = False

    with pytest.raises(IDAError) as excinfo:
        function_type_mod.apply_call_site_type(CALL_EA, object(), FUNC_START)

    assert excinfo.value.error_type == "ApplyFailed"
    ida_hexrays.mark_cfunc_dirty.assert_not_called()


def test_clear_call_site_type_refuses_when_no_operand_type(function_type_mod):
    ida_nalt.get_op_tinfo.return_value = False

    with pytest.raises(IDAError) as excinfo:
        function_type_mod.clear_call_site_type(CALL_EA, FUNC_START)

    assert excinfo.value.error_type == "NotFound"
    ida_nalt.del_op_tinfo.assert_not_called()
    ida_hexrays.mark_cfunc_dirty.assert_not_called()


def test_clear_call_site_type_deletes_operand_type_then_marks_dirty(function_type_mod):
    ida_nalt.get_op_tinfo.return_value = True

    function_type_mod.clear_call_site_type(CALL_EA, FUNC_START)

    ida_nalt.del_op_tinfo.assert_called_once_with(CALL_EA, 0)
    ida_hexrays.mark_cfunc_dirty.assert_called_once_with(FUNC_START, False)


# ---------------------------------------------------------------------------
# set_stack_delta / delete_stack_delta (tools/frames.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def frames_mod(monkeypatch):
    mod = importlib.import_module("re_mcp_ida.tools.frames")
    # `sub rsp, 30h` at 0x1000 is 4 bytes; IDA keeps the stack point at its end.
    monkeypatch.setattr(mod, "decode_insn_at", lambda ea: SimpleNamespace(ea=ea, size=4))
    ida_nalt.is_usersp.reset_mock()
    ida_frame.del_stkpnt.reset_mock()
    return mod


def test_stack_point_ea_is_instruction_end(frames_mod):
    assert frames_mod.stack_point_ea(0x1000) == 0x1004


def test_delete_stack_delta_refuses_auto_points(frames_mod):
    func = object()
    ida_nalt.is_usersp.return_value = False

    with pytest.raises(IDAError) as excinfo:
        frames_mod.delete_user_stack_point(func, 0x1000)

    assert excinfo.value.error_type == "NotFound"
    ida_nalt.is_usersp.assert_called_once_with(0x1004)
    ida_frame.del_stkpnt.assert_not_called()


def test_delete_stack_delta_removes_user_point_at_instruction_end(frames_mod):
    func = object()
    ida_nalt.is_usersp.return_value = True
    ida_frame.del_stkpnt.return_value = True

    assert frames_mod.delete_user_stack_point(func, 0x1000) == 0x1004

    ida_frame.del_stkpnt.assert_called_once_with(func, 0x1004)


# ---------------------------------------------------------------------------
# get_ctree call flags / find_ctree_patterns string refs (tools/ctree.py)
# ---------------------------------------------------------------------------

# hexrays.hpp: CFL_FINAL 0x0001, CFL_HELPER 0x0002, CFL_NORET 0x0004
_CFL_CONSTANTS = {"CFL_FINAL": 0x1, "CFL_HELPER": 0x2, "CFL_NORET": 0x4}


@pytest.fixture(scope="module")
def ctree_mod():
    for name, value in _CFL_CONSTANTS.items():
        setattr(ida_hexrays, name, value)
    # the flag tables are built at import time, so (re)load after the constants exist
    return importlib.reload(importlib.import_module("re_mcp_ida.tools.ctree"))


class _EmptyCarglist:
    """Mimics ``carglist_t``: ``__len__`` only, no ``__bool__`` (so it is falsy when empty)."""

    def __init__(self, flags: int):
        self.flags = flags

    def __len__(self) -> int:
        return 0


def test_call_flags_kept_for_zero_arg_call(ctree_mod):
    expr = SimpleNamespace(a=_EmptyCarglist(flags=0x3))
    assert not expr.a  # the trap the contributor code fell into

    assert ctree_mod._call_flags(expr) == ["FINAL", "HELPER"]


def test_call_flags_empty_without_arglist(ctree_mod):
    assert ctree_mod._call_flags(SimpleNamespace(a=None)) == []


@pytest.fixture
def strlit_stubs():
    ida_bytes.get_flags.reset_mock()
    ida_bytes.is_strlit.reset_mock()
    ida_bytes.get_max_strlit_length.reset_mock()
    ida_bytes.get_strlit_contents.reset_mock()
    ida_nalt.get_str_type.reset_mock()
    ida_bytes.get_flags.return_value = 0x500
    ida_nalt.get_str_type.return_value = ida_nalt.STRTYPE_C
    ida_bytes.get_max_strlit_length.return_value = 8
    ida_bytes.get_strlit_contents.return_value = b"PARSER2"


def test_obj_string_returns_none_for_non_strlit(ctree_mod, strlit_stubs):
    ida_bytes.is_strlit.return_value = False

    assert ctree_mod._obj_string(0x140001010) is None

    ida_bytes.is_strlit.assert_called_once_with(0x500)
    ida_bytes.get_max_strlit_length.assert_not_called()


def test_obj_string_decodes_strlit(ctree_mod, strlit_stubs):
    ida_bytes.is_strlit.return_value = True

    assert ctree_mod._obj_string(0x14000A690) == "PARSER2"

    ida_bytes.get_max_strlit_length.assert_called_once_with(0x14000A690, ida_nalt.STRTYPE_C)


def test_obj_string_returns_none_for_empty_strlit(ctree_mod, strlit_stubs):
    ida_bytes.is_strlit.return_value = True
    ida_bytes.get_max_strlit_length.return_value = 0

    assert ctree_mod._obj_string(0x14000A690) is None
    ida_bytes.get_strlit_contents.assert_not_called()
