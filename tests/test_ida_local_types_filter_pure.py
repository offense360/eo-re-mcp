# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Issue #35 — ``list_local_types`` accepts ``filter_pattern`` like Ghidra.

The Ghidra tool filters on the type *name* with ``compile_filter`` (regex,
case-insensitive, substring search).  The IDA tool gained the same parameter;
its per-ordinal loop lives in ``iter_local_types(til, filt)`` so it can run
against the ``conftest`` idalib stubs.
"""

from __future__ import annotations

import ast
import importlib
import inspect
from pathlib import Path
from unittest.mock import MagicMock

import ida_kernwin
import ida_typeinf
import pytest
from re_mcp_ida.helpers import compile_filter

pytestmark = pytest.mark.skipif(
    not isinstance(ida_typeinf, MagicMock), reason="real idalib installed; stub-only tests"
)

_TYPEINF_PY = (
    Path(__file__).resolve().parents[1] / "packages/re-mcp-ida/src/re_mcp_ida/tools/typeinf.py"
)

TIL = object()
# ordinal -> name; ordinal 2 has no name and must be skipped
NAMES = {1: "CURLoption", 2: "", 3: "sockaddr_in", 4: "curl_slist"}


@pytest.fixture
def typeinf_mod(monkeypatch):
    """Configure the shared idalib stubs through ``monkeypatch`` so the
    ``side_effect``/``return_value`` settings are undone after each test and
    do not leak into other stub-based test modules."""
    mod = importlib.import_module("re_mcp_ida.tools.typeinf")
    monkeypatch.setattr(ida_kernwin.user_cancelled, "return_value", False)
    monkeypatch.setattr(ida_typeinf.get_ordinal_count, "side_effect", None)
    monkeypatch.setattr(ida_typeinf.get_ordinal_count, "return_value", len(NAMES))
    monkeypatch.setattr(
        ida_typeinf.get_numbered_type_name, "side_effect", lambda til, ordinal: NAMES[ordinal]
    )
    tinfo = ida_typeinf.tinfo_t.return_value
    monkeypatch.setattr(tinfo.get_numbered_type, "return_value", True)
    monkeypatch.setattr(tinfo.get_size, "return_value", 8)
    monkeypatch.setattr(tinfo.__str__, "return_value", "struct x")
    for flag in ("is_struct", "is_union", "is_enum", "is_typedef"):
        monkeypatch.setattr(getattr(tinfo, flag), "return_value", False)
    return mod


def _names(mod, filt):
    return [item["name"] for item in mod.iter_local_types(TIL, filt)]


def test_no_filter_lists_every_named_type(typeinf_mod):
    assert _names(typeinf_mod, compile_filter("")) == ["CURLoption", "sockaddr_in", "curl_slist"]


def test_filter_matches_the_type_name_case_insensitively(typeinf_mod):
    assert _names(typeinf_mod, compile_filter("^curl_")) == ["curl_slist"]
    assert _names(typeinf_mod, compile_filter("^curl")) == ["CURLoption", "curl_slist"]


def test_filter_without_match_yields_nothing(typeinf_mod):
    assert _names(typeinf_mod, compile_filter("nosuchtype_zz")) == []


def test_items_keep_the_summary_shape(typeinf_mod):
    (item,) = list(typeinf_mod.iter_local_types(TIL, compile_filter("sockaddr")))

    assert item == {
        "ordinal": 3,
        "name": "sockaddr_in",
        "type": "struct x",
        "size": 8,
        "is_struct": False,
        "is_union": False,
        "is_enum": False,
        "is_typedef": False,
    }


def test_tool_signature_and_body_use_filter_pattern(typeinf_mod):
    tree = ast.parse(_TYPEINF_PY.read_text(encoding="utf-8"))
    tool = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "list_local_types"
    )
    params = {a.arg: ast.unparse(a.annotation) for a in tool.args.args if a.annotation}
    assert params.get("filter_pattern") == "FilterPattern"
    called = {ast.unparse(n.func) for n in ast.walk(tool) if isinstance(n, ast.Call)}
    assert "compile_filter" in called
    assert "iter_local_types" in called
    assert "filter_pattern: Optional regex matched against the type name" in inspect.getsource(
        typeinf_mod
    )
