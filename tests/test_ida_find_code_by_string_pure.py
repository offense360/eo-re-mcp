# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Issue #37 — ``find_code_by_string`` returns the paginated envelope with
``code_address`` on IDA, like Ghidra.

The tool used to stop scanning at ``limit`` (so ``total_strings_scanned`` was
just the page size) and dropped ``xref.frm``, the referencing instruction.
It now scans every matching string and xref through ``collect_string_refs``
and pages the result with core ``paginate``, so ``total``/``has_more`` are
exact and ``unique_functions``/``total_strings_scanned`` describe the whole
database.  Runs against the ``conftest`` idalib stubs.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import ida_funcs
import ida_kernwin
import ida_name
import idautils
import pytest
from pydantic import ValidationError

pytestmark = pytest.mark.skipif(
    not isinstance(ida_funcs, MagicMock), reason="real idalib installed; stub-only tests"
)

_SEARCH_PY = (
    Path(__file__).resolve().parents[1] / "packages/re-mcp-ida/src/re_mcp_ida/tools/search.py"
)

STRINGS = [
    {"ea": 0x500000, "address": "0x500000", "value": "CURLOPT_A", "length": 9, "type": 0},
    {"ea": 0x500010, "address": "0x500010", "value": "CURLOPT_B", "length": 9, "type": 0},
]
# string ea -> referencing instruction addresses (0x401234 is not inside any function)
XREFS = {0x500000: [0x401004, 0x401234, 0x402008], 0x500010: [0x401010]}
FUNC_OF = {0x401004: 0x401000, 0x402008: 0x402000, 0x401010: 0x401000}
NAMES = {0x401000: "ssh_setopts", 0x402000: "other_setopts"}


@pytest.fixture
def search_mod(monkeypatch):
    mod = importlib.import_module("re_mcp_ida.tools.search")
    monkeypatch.setattr(ida_kernwin.user_cancelled, "return_value", False)
    monkeypatch.setattr(
        idautils.XrefsTo,
        "side_effect",
        lambda ea: [SimpleNamespace(frm=frm, to=ea) for frm in XREFS.get(ea, [])],
    )
    monkeypatch.setattr(
        ida_funcs.get_func,
        "side_effect",
        lambda ea: SimpleNamespace(start_ea=FUNC_OF[ea]) if ea in FUNC_OF else None,
    )
    monkeypatch.setattr(ida_name.get_name, "side_effect", lambda ea: NAMES.get(ea, ""))
    return mod


def test_collects_every_reference_with_code_address(search_mod):
    refs, scanned = search_mod.collect_string_refs(iter(STRINGS))

    assert scanned == 2
    assert [r["code_address"] for r in refs] == ["0x401004", "0x402008", "0x401010"]
    assert refs[0] == {
        "string_address": "0x500000",
        "string_value": "CURLOPT_A",
        "code_address": "0x401004",
        "function_name": "ssh_setopts",
        "function_address": "0x401000",
    }


def test_reference_outside_any_function_is_dropped(search_mod):
    refs, _ = search_mod.collect_string_refs(iter(STRINGS))

    assert "0x401234" not in {r["code_address"] for r in refs}


def test_page_envelope_counts_the_whole_database(search_mod):
    refs, scanned = search_mod.collect_string_refs(iter(STRINGS))

    first = search_mod.build_find_code_result(refs, scanned, offset=0, limit=2)
    assert [i.code_address for i in first.items] == ["0x401004", "0x402008"]
    assert (first.total, first.offset, first.limit, first.has_more) == (3, 0, 2, True)
    assert first.total_strings_scanned == 2
    assert first.unique_functions == 2

    second = search_mod.build_find_code_result(refs, scanned, offset=2, limit=2)
    assert [i.code_address for i in second.items] == ["0x401010"]
    assert (second.total, second.has_more) == (3, False)
    # whole-database figures do not shrink on later pages
    assert second.unique_functions == 2
    assert second.total_strings_scanned == 2

    beyond = search_mod.build_find_code_result(refs, scanned, offset=100000, limit=2)
    assert beyond.items == []
    assert (beyond.total, beyond.has_more) == (3, False)


def test_result_model_is_the_paginated_envelope(search_mod):
    fields = search_mod.FindCodeByStringResult.model_fields
    assert {"items", "total", "offset", "limit", "has_more"} <= set(fields)
    assert "results" not in fields
    assert "whole database" in fields["total_strings_scanned"].description
    assert "not just this page" in fields["unique_functions"].description

    ref_fields = search_mod.StringCodeRef.model_fields
    assert list(ref_fields) == [
        "string_address",
        "string_value",
        "code_address",
        "function_name",
        "function_address",
    ]
    assert ref_fields["code_address"].is_required()
    assert "get_xrefs_from" in ref_fields["code_address"].description
    with pytest.raises(ValidationError):
        search_mod.StringCodeRef.model_validate(
            {
                "string_address": "0x500000",
                "string_value": "s",
                "function_address": "0x401000",
                "function_name": "f",
            }
        )


def test_tool_scans_everything_then_paginates(search_mod):
    tree = ast.parse(_SEARCH_PY.read_text(encoding="utf-8"))
    tool = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "find_code_by_string"
    )
    called = {ast.unparse(n.func) for n in ast.walk(tool) if isinstance(n, ast.Call)}
    assert "collect_string_refs" in called
    assert "build_find_code_result" in called
    assert "paginated envelope as Ghidra" in ast.get_docstring(tool)

    builder = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "build_find_code_result"
    )
    assert "paginate" in {ast.unparse(n.func) for n in ast.walk(builder) if isinstance(n, ast.Call)}
