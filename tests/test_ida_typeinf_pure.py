# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Issue #32 — parse_type_declaration explains why a declaration failed.

Under idalib ``ida_typeinf.parse_decls`` only returns an error *count*: its
``printer`` argument cannot be a Python callable and nothing reaches the
message window.  ``diagnose_declaration`` therefore runs our own checks on
the failed text (bracket balance, trailing ``;``, unknown type names) and
the tool folds them, plus IDA's error count, into the ``ParseError``
message.  Runs without idalib: ``ida_typeinf`` is a ``MagicMock`` stub from
``conftest``.
"""

from __future__ import annotations

import importlib
from unittest.mock import MagicMock

import ida_typeinf
import pytest
from re_mcp_ida.helpers import IDAError

pytestmark = pytest.mark.skipif(
    not isinstance(ida_typeinf, MagicMock), reason="real idalib installed; stub-only tests"
)

KNOWN_TYPES = {"known_t"}
TIL = object()


@pytest.fixture
def typeinf_mod():
    mod = importlib.import_module("re_mcp_ida.tools.typeinf")
    ida_typeinf.parse_decls.reset_mock()
    ida_typeinf.parse_decl.reset_mock()
    ida_typeinf.get_idati.return_value = TIL
    tinfo = ida_typeinf.tinfo_t.return_value
    tinfo.get_named_type.side_effect = lambda til, name, *a: name in KNOWN_TYPES
    tinfo.get_size.return_value = 8
    return mod


# ---------------------------------------------------------------------------
# diagnose_declaration
# ---------------------------------------------------------------------------


def test_unbalanced_brace_reported(typeinf_mod):
    diags = typeinf_mod.diagnose_declaration("struct broken { int a; ", TIL)

    joined = "; ".join(diags)
    assert "unbalanced '{' (1 open, 0 close)" in joined
    assert "does not end with ';'" in joined


def test_unknown_type_reported(typeinf_mod):
    diags = typeinf_mod.diagnose_declaration("struct broken2 { nosuchtype_t a; };", TIL)

    assert diags == ["unknown type 'nosuchtype_t'"]


def test_known_types_not_reported(typeinf_mod):
    diags = typeinf_mod.diagnose_declaration(
        "struct ok_t { int a; unsigned __int64 b; known_t c; };", TIL
    )

    assert diags == []


def test_member_and_tag_names_are_not_types(typeinf_mod):
    """Only identifiers in type position are looked up; declarator names,
    struct tags, typedef aliases and function-pointer names are not."""
    decl = (
        "typedef struct my_tag { int (*cb)(int, known_t); nosuchtype_t x; char buf[16]; } my_alias;"
    )

    diags = typeinf_mod.diagnose_declaration(decl, TIL)

    assert diags == ["unknown type 'nosuchtype_t'"]


def test_missing_semicolon_only_for_type_declarations(typeinf_mod):
    assert typeinf_mod.diagnose_declaration("int (*fp)(int, char)", TIL) == []


# ---------------------------------------------------------------------------
# parse_declaration (the tool body)
# ---------------------------------------------------------------------------


def test_message_carries_error_count(typeinf_mod):
    ida_typeinf.parse_decls.return_value = 2
    ida_typeinf.parse_decl.return_value = None

    with pytest.raises(IDAError) as ei:
        typeinf_mod.parse_declaration("struct broken2 { nosuchtype_t a; };")

    assert ei.value.error_type == "ParseError"
    msg = ei.value.args[0]
    assert msg.startswith("Failed to parse declaration (2 error(s)): ")
    assert "unknown type 'nosuchtype_t'" in msg


def test_message_admits_when_nothing_was_found(typeinf_mod):
    ida_typeinf.parse_decls.return_value = 1
    ida_typeinf.parse_decl.return_value = None

    with pytest.raises(IDAError) as ei:
        typeinf_mod.parse_declaration("struct ok_t { int a; };")

    assert "IDA reported 1 error(s) but exposes no diagnostics under idalib" in ei.value.args[0]


def test_fallback_anonymous_type_still_works(typeinf_mod):
    ida_typeinf.parse_decls.return_value = 1
    ida_typeinf.parse_decl.return_value = object()

    result = typeinf_mod.parse_declaration("int (*fp)(int, char)")

    assert result.saved is False
    assert result.size == 8
    assert "not saved" in result.message


def test_success_path_never_diagnoses(typeinf_mod, monkeypatch):
    ida_typeinf.parse_decls.return_value = 0
    ida_typeinf.get_ordinal_count.side_effect = [3, 4]
    ida_typeinf.get_numbered_type_name.return_value = "ok32"

    def _boom(*a, **k):
        raise AssertionError("diagnose_declaration must not run on success")

    monkeypatch.setattr(typeinf_mod, "diagnose_declaration", _boom)

    result = typeinf_mod.parse_declaration("struct ok32 { int a; char b[4]; };")

    assert result.saved is True
    assert result.name == "ok32"


# ---------------------------------------------------------------------------
# enum bodies: enumerators are not type names
# ---------------------------------------------------------------------------


def test_enum_enumerators_are_not_types(typeinf_mod):
    diags = typeinf_mod.diagnose_declaration("enum E { A = 1, B }", TIL)

    assert diags == ["declaration does not end with ';'"]


@pytest.mark.parametrize(
    "decl",
    ["enum E { A, B };", "typedef enum { A = 1, B = A + 1 } e_t;"],
)
def test_valid_enum_has_no_diagnostics(typeinf_mod, decl):
    assert typeinf_mod.diagnose_declaration(decl, TIL) == []


def test_enum_member_type_in_struct_is_still_checked(typeinf_mod):
    diags = typeinf_mod.diagnose_declaration("struct S { enum E e; foo_t f; };", TIL)

    assert diags == ["unknown type 'foo_t'"]
