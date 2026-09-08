# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Issue #40 — ``get_pseudocode_line_map`` is built from the pseudocode anchors.

Every token of a Hex-Rays pseudocode line carries a ``COLOR_ON COLOR_ADDR``
tag followed by ``COLOR_ADDR_SIZE`` hex digits holding a ``ctree_anchor_t``.
``iter_line_anchors`` decodes those anchors and ``build_line_map`` applies
rule T: per line the lowest ``ea`` among the anchored ctree items, skipping
``cit_switch`` (its anchor sits on every ``case`` line) and counting a
``cit_block`` anchor only on the first line it appears (so ``}`` lines do
not map to the block start).  The tool must not call ``find_item_coords``
any more (one ~1 ms lookup per ctree item was the whole cost).

Runs on the ``conftest`` idalib stubs: ``ida_lines`` colour constants,
``ida_hexrays.cit_*`` and ``ctree_anchor_t`` are monkeypatched with the
IDA 9.4 encoding (``ANCHOR_MASK`` 0xC0000000: citem = 0, lvar = 0x40000000,
index = ``value & 0x1FFFFFFF``).
"""

from __future__ import annotations

import ast
import importlib
import inspect
from types import SimpleNamespace
from unittest.mock import MagicMock

import ida_hexrays
import ida_lines
import ida_nalt
import pytest

pytestmark = pytest.mark.skipif(
    not isinstance(ida_nalt, MagicMock), reason="real idalib installed; stub-only tests"
)

COLOR_ON = "\x01"
COLOR_ADDR = "\x28"
COLOR_ADDR_SIZE = 16

# ctype_t values (any distinct integers will do for the fake).
COT_VAR = 5
COT_LAND = 25
COT_CALL = 57
CIT_BLOCK = 71
CIT_EXPR = 72
CIT_IF = 73
CIT_SWITCH = 77

BADADDR = 0xFFFFFFFFFFFFFFFF

ANCHOR_MASK = 0xC0000000
ANCHOR_CITEM = 0x00000000
ANCHOR_LVAR = 0x40000000
ANCHOR_ITP = 0x80000000
ANCHOR_BLKCMT = 0xC0000000
ANCHOR_INDEX_MASK = 0x1FFFFFFF


class FakeCtreeAnchor:
    """``ida_hexrays.ctree_anchor_t`` stand-in with the IDA 9.4 bit layout."""

    def __init__(self) -> None:
        self._value = 0
        self._kind = ANCHOR_CITEM

    @property
    def value(self) -> int:
        return self._value

    @value.setter
    def value(self, val: int) -> None:
        self._value = val
        self._kind = val & ANCHOR_MASK

    def get_index(self) -> int:
        return self._value & ANCHOR_INDEX_MASK

    def is_citem_anchor(self) -> bool:
        return self._kind == ANCHOR_CITEM

    def is_lvar_anchor(self) -> bool:
        return self._kind == ANCHOR_LVAR

    def is_itp_anchor(self) -> bool:
        return self._kind == ANCHOR_ITP

    def is_blkcmt_anchor(self) -> bool:
        return self._kind == ANCHOR_BLKCMT


class FakeStrvec:
    """``strvec_t`` stand-in: ``size()`` and ``sv[i].line``."""

    def __init__(self, lines: list[str]) -> None:
        self._lines = [SimpleNamespace(line=text) for text in lines]

    def size(self) -> int:
        return len(self._lines)

    def __len__(self) -> int:
        return len(self._lines)

    def __getitem__(self, i: int) -> SimpleNamespace:
        return self._lines[i]


def anchor(index: int, kind: int = ANCHOR_CITEM) -> str:
    """Render the tag Hex-Rays emits in front of a token."""
    return COLOR_ON + COLOR_ADDR + f"{kind | index:0{COLOR_ADDR_SIZE}X}"


def item(ea: int, op: int = CIT_EXPR) -> SimpleNamespace:
    return SimpleNamespace(ea=ea, op=op, index=-1, is_expr=lambda: op < CIT_BLOCK)


def make_cfunc(lines: list[str], items: list[SimpleNamespace]) -> SimpleNamespace:
    # ``treeitems[i].index`` is the item's position in the vector.
    for i, it in enumerate(items):
        it.index = i
    sv = FakeStrvec(lines)
    return SimpleNamespace(
        get_pseudocode=lambda: sv,
        treeitems=items,
        hdrlines=0,
        find_item_coords=MagicMock(side_effect=AssertionError("find_item_coords must not be used")),
    )


@pytest.fixture
def decompiler(monkeypatch):
    monkeypatch.setattr(ida_lines, "COLOR_ON", COLOR_ON, raising=False)
    monkeypatch.setattr(ida_lines, "COLOR_ADDR", COLOR_ADDR, raising=False)
    monkeypatch.setattr(ida_lines, "COLOR_ADDR_SIZE", COLOR_ADDR_SIZE, raising=False)
    monkeypatch.setattr(ida_hexrays, "cit_block", CIT_BLOCK, raising=False)
    monkeypatch.setattr(ida_hexrays, "cit_switch", CIT_SWITCH, raising=False)
    monkeypatch.setattr(ida_hexrays, "ctree_anchor_t", FakeCtreeAnchor, raising=False)
    return importlib.import_module("re_mcp_ida.tools.decompiler")


# ---------------------------------------------------------------------------
# iter_line_anchors
# ---------------------------------------------------------------------------


def test_iter_line_anchors_yields_citem_indexes_in_order(decompiler):
    line = "  " + anchor(7) + "v3 = " + anchor(12) + "foo(" + anchor(3) + "a);"
    assert list(decompiler.iter_line_anchors(line)) == [7, 12, 3]


def test_iter_line_anchors_skips_lvar_itp_and_blkcmt_anchors(decompiler):
    line = (
        anchor(4, ANCHOR_LVAR)
        + "v1"
        + anchor(9)
        + " = "
        + anchor(2, ANCHOR_ITP)
        + anchor(1, ANCHOR_BLKCMT)
        + "x;"
    )
    assert list(decompiler.iter_line_anchors(line)) == [9]


def test_iter_line_anchors_ignores_non_hex_and_truncated_anchors(decompiler):
    bad = COLOR_ON + COLOR_ADDR + "ZZZZZZZZZZZZZZZZ"
    short = COLOR_ON + COLOR_ADDR + "00000000000"
    line = bad + "a" + anchor(5) + "b" + short
    assert list(decompiler.iter_line_anchors(line)) == [5]


def test_iter_line_anchors_on_plain_text_is_empty(decompiler):
    assert list(decompiler.iter_line_anchors("}")) == []
    assert list(decompiler.iter_line_anchors("")) == []


@pytest.mark.parametrize(
    ("color_on", "color_addr"),
    [(0x01, 0x28), ("\x01", 0x28), (0x01, "\x28")],
    ids=["both-int", "addr-int", "on-int"],
)
def test_iter_line_anchors_accepts_integer_colour_constants(
    decompiler, monkeypatch, color_on, color_addr
):
    """idalib on IDA 9.4 exposes the colour code as an ``int`` (the worker
    raised ``can only concatenate str (not "int") to str`` on the VM)."""
    monkeypatch.setattr(ida_lines, "COLOR_ON", color_on, raising=False)
    monkeypatch.setattr(ida_lines, "COLOR_ADDR", color_addr, raising=False)
    assert list(decompiler.iter_line_anchors(anchor(6) + "x" + anchor(2))) == [6, 2]


# ---------------------------------------------------------------------------
# build_line_map — rule T
# ---------------------------------------------------------------------------


def test_line_maps_to_lowest_ea_of_its_anchors(decompiler):
    items = [item(0x30, COT_CALL), item(0x20, COT_VAR)]
    cfunc = make_cfunc([anchor(0) + "f(" + anchor(1) + "v1);"], items)
    assert decompiler.build_line_map(cfunc) == {0: 0x20}


def test_line_with_only_lvar_anchors_is_absent(decompiler):
    items = [item(0x10)]
    cfunc = make_cfunc(["  int " + anchor(0, ANCHOR_LVAR) + "v1;"], items)
    assert decompiler.build_line_map(cfunc) == {}


def test_switch_anchor_is_ignored(decompiler):
    switch = item(0x100, CIT_SWITCH)
    body = item(0x140, CIT_EXPR)
    items = [switch, body]
    cfunc = make_cfunc(
        [
            anchor(0) + "switch ( v1 )",
            anchor(0) + "{",
            anchor(0) + "  case 1:",
            anchor(0) + "    " + anchor(1) + "g();",
        ],
        items,
    )
    assert decompiler.build_line_map(cfunc) == {3: 0x140}


def test_block_anchor_counts_only_on_its_first_line(decompiler):
    block = item(0x200, CIT_BLOCK)
    stmt = item(0x210, CIT_EXPR)
    items = [block, stmt]
    cfunc = make_cfunc(
        [
            anchor(0) + "{",
            anchor(0) + "  " + anchor(1) + "h();",
            anchor(0) + "}",
        ],
        items,
    )
    assert decompiler.build_line_map(cfunc) == {0: 0x200, 1: 0x210}


def test_distinct_blocks_each_count_on_their_own_first_line(decompiler):
    outer = item(0x300, CIT_BLOCK)
    inner = item(0x320, CIT_BLOCK)
    items = [outer, inner]
    cfunc = make_cfunc(
        [
            anchor(0) + "{",
            anchor(0) + "  " + anchor(1) + "{",
            anchor(0) + "  " + anchor(1) + "}",
            anchor(0) + "}",
        ],
        items,
    )
    assert decompiler.build_line_map(cfunc) == {0: 0x300, 1: 0x320}


def test_badaddr_items_are_ignored(decompiler):
    items = [item(BADADDR, COT_VAR), item(0x40, CIT_EXPR)]
    cfunc = make_cfunc([anchor(0) + "v1" + anchor(1) + " = 1;", anchor(0) + "v1;"], items)
    assert decompiler.build_line_map(cfunc) == {0: 0x40}


def test_out_of_range_indexes_are_ignored(decompiler):
    items = [item(0x50)]
    cfunc = make_cfunc([anchor(1) + "x" + anchor(0) + "y", anchor(99) + "z"], items)
    assert decompiler.build_line_map(cfunc) == {0: 0x50}


def test_non_hex_anchor_values_are_ignored(decompiler):
    items = [item(0x60)]
    bad = COLOR_ON + COLOR_ADDR + "0000000000000G00"
    cfunc = make_cfunc([bad + "x", bad + anchor(0) + "y"], items)
    assert decompiler.build_line_map(cfunc) == {1: 0x60}


def test_label_and_continuation_lines_are_included(decompiler):
    """Lines that ``find_item_coords`` never reported: a label and the second
    line of a multi-line condition both carry anchors of the statement."""
    cond = item(0x400, CIT_IF)
    land = item(0x40A, COT_LAND)
    call = item(0x410, COT_CALL)
    items = [cond, land, call]
    cfunc = make_cfunc(
        [
            anchor(0) + "LABEL_3:",
            anchor(0) + "if ( " + anchor(1) + "a",
            anchor(0) + "  && " + anchor(1) + anchor(2) + "b() )",
        ],
        items,
    )
    assert decompiler.build_line_map(cfunc) == {0: 0x400, 1: 0x400, 2: 0x400}


def test_build_line_map_never_calls_find_item_coords(decompiler):
    cfunc = make_cfunc([anchor(0) + "x;"], [item(0x70)])
    decompiler.build_line_map(cfunc)
    cfunc.find_item_coords.assert_not_called()


# ---------------------------------------------------------------------------
# Tool body wiring (source inspection)
# ---------------------------------------------------------------------------


def _tool_def(mod, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    tree = ast.parse(inspect.getsource(mod))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{name} not found")


def test_tool_uses_build_line_map_and_not_find_item_coords(decompiler):
    fn = _tool_def(decompiler, "get_pseudocode_line_map")
    attrs = {n.attr for n in ast.walk(fn) if isinstance(n, ast.Attribute)}
    calls = {
        n.func.id for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    assert "find_item_coords" not in attrs
    assert "build_line_map" in calls


def test_tool_docstring_describes_anchor_pass(decompiler):
    fn = _tool_def(decompiler, "get_pseudocode_line_map")
    doc = ast.get_docstring(fn) or ""
    assert "anchor" in doc
    assert "label" in doc
    assert "switch" in doc
    assert "}" in doc


def test_result_model_lines_field_mentions_rule(decompiler):
    desc = decompiler.PseudocodeLineMapResult.model_fields["lines"].description or ""
    assert "lowest" in desc
    assert "switch" in desc
