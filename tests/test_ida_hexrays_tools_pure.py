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
from unittest.mock import MagicMock

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
