# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Unit tests for the Ghidra cross-reference filter — no Ghidra required.

``re_mcp_ghidra.tools.xrefs`` only touches Ghidra through the objects it is
handed, so the module-level helpers can be exercised with fakes shaped like
``ghidra.program.model.symbol.Reference`` and
``ghidra.program.model.address.Address``.
"""

from __future__ import annotations

import ast
import pathlib

import pytest
from re_mcp.helpers import paginate_iter
from re_mcp_ghidra.tools import switches as switches_mod
from re_mcp_ghidra.tools.xrefs import (
    XrefsFromResult,
    collect_xrefs_from,
    is_memory_reference,
)


class FakeRefAddr:
    """Stands in for ``Address``: only the calls the filters make."""

    def __init__(self, offset: int, *, memory: bool = True, external: bool = False) -> None:
        self.offset = offset
        self.memory = memory
        self.external = external

    def getOffset(self) -> int:
        return self.offset

    def isMemoryAddress(self) -> bool:
        return self.memory

    def isExternalAddress(self) -> bool:
        return self.external


class FakeRefType:
    def __init__(self, name: str, *, call: bool = False) -> None:
        self.name = name
        self.call = call

    def isCall(self) -> bool:
        return self.call

    def __str__(self) -> str:
        return self.name


class FakeRef:
    """Stands in for ``Reference``."""

    def __init__(
        self,
        to: FakeRefAddr | None,
        ref_type: FakeRefType | None = None,
        *,
        stack: bool = False,
        register: bool = False,
        external: bool = False,
    ) -> None:
        self.to = to
        self.ref_type = ref_type or FakeRefType("DATA")
        self.stack = stack
        self.register = register
        self.external = external

    def getToAddress(self) -> FakeRefAddr | None:
        return self.to

    def isStackReference(self) -> bool:
        return self.stack

    def isRegisterReference(self) -> bool:
        return self.register

    def isExternalReference(self) -> bool:
        return self.external

    def getReferenceType(self) -> FakeRefType:
        return self.ref_type


def memory_ref(offset: int = 0x140007D00) -> FakeRef:
    return FakeRef(FakeRefAddr(offset), FakeRefType("CALL", call=True))


def stack_ref(offset: int = 0x8) -> FakeRef:
    """``mov [rsp+8], rbx`` produces a WRITE reference to ``Stack[0x8]``."""
    return FakeRef(FakeRefAddr(offset, memory=False), FakeRefType("WRITE"), stack=True)


def register_ref(offset: int = 0x10) -> FakeRef:
    return FakeRef(FakeRefAddr(offset, memory=False), FakeRefType("READ"), register=True)


def external_ref(offset: int = 0xB0) -> FakeRef:
    """A call to an imported symbol targets Ghidra's artificial EXTERNAL space.

    ``isMemoryAddress()`` is false there, so the address behaves like the stack
    one: ``0xB0`` looks like memory but no other tool can resolve it.
    """
    return FakeRef(
        FakeRefAddr(offset, memory=False, external=True),
        FakeRefType("UNCONDITIONAL_CALL", call=True),
        external=True,
    )


def _to_address(ref: FakeRef) -> dict:
    """A stand-in for the tool's renderer, shaped like ``XrefFrom``."""
    ref_type = ref.getReferenceType()
    return {
        "to_address": f"0x{ref.getToAddress().getOffset():X}",
        "to_function": "",
        "ref_type": str(ref_type),
        "is_call": ref_type.isCall(),
    }


class TestIsMemoryReference:
    """#30: only references into a real memory space may be rendered as
    addresses.  A ``Stack[0x8]`` target printed as ``0x8`` is indistinguishable
    from memory address 8, and feeding it back to another tool answers
    "No code unit at 0x8"."""

    def test_memory_reference_is_kept(self):
        assert is_memory_reference(memory_ref()) is True

    def test_stack_reference_is_rejected(self):
        assert is_memory_reference(stack_ref()) is False

    def test_register_reference_is_rejected(self):
        assert is_memory_reference(register_ref()) is False

    def test_reference_with_no_target_address_is_rejected(self):
        assert is_memory_reference(FakeRef(None)) is False

    def test_external_reference_is_rejected(self):
        """A reference to an imported symbol lives in the EXTERNAL space, which
        is not a memory space -- so it is dropped too, deliberately.  Its offset
        is a slot index (`free` sits at `0xB0`), not an address any other tool
        can resolve."""
        assert is_memory_reference(external_ref()) is False

    def test_stack_flag_alone_rejects_even_a_memory_looking_address(self):
        ref = FakeRef(FakeRefAddr(0x8, memory=True), stack=True)
        assert is_memory_reference(ref) is False

    def test_register_flag_alone_rejects_even_a_memory_looking_address(self):
        ref = FakeRef(FakeRefAddr(0x10, memory=True), register=True)
        assert is_memory_reference(ref) is False


class TestCollectXrefsFrom:
    def test_keeps_memory_refs_and_counts_the_rest(self):
        refs = [memory_ref(), stack_ref(), register_ref()]
        items, skipped = collect_xrefs_from(refs, _to_address)
        assert items == [
            {
                "to_address": "0x140007D00",
                "to_function": "",
                "ref_type": "CALL",
                "is_call": True,
            }
        ]
        assert skipped == 2

    def test_external_reference_is_kept_as_an_item(self):
        """A thunk that references an imported symbol yields an item (rendered
        by the tool as ``EXTERNAL:<library>::<name>``, #43); only stack,
        register and constant targets count as ``skipped_non_memory``."""
        items, skipped = collect_xrefs_from([memory_ref(), external_ref()], _to_address)
        assert len(items) == 2
        assert skipped == 0

    def test_external_is_kept_while_stack_and_register_are_still_skipped(self):
        refs = [external_ref(), stack_ref(), memory_ref(), register_ref()]
        items, skipped = collect_xrefs_from(refs, _to_address)
        assert [i["to_address"] for i in items] == ["0xB0", "0x140007D00"]
        assert skipped == 2

    def test_none_target_is_counted_as_skipped(self):
        items, skipped = collect_xrefs_from([memory_ref(), FakeRef(None)], _to_address)
        assert len(items) == 1
        assert skipped == 1

    def test_builder_is_never_called_for_a_skipped_ref(self):
        seen: list[FakeRef] = []

        def _build(ref: FakeRef) -> dict:
            seen.append(ref)
            return _to_address(ref)

        kept = memory_ref()
        collect_xrefs_from([stack_ref(), kept, register_ref()], _build)
        assert seen == [kept]

    def test_no_refs_yields_no_items_and_no_skips(self):
        assert collect_xrefs_from([], _to_address) == ([], 0)

    def test_all_refs_skipped_leaves_items_empty(self):
        items, skipped = collect_xrefs_from([stack_ref(), register_ref()], _to_address)
        assert items == []
        assert skipped == 2

    def test_consumes_an_iterator_so_the_count_covers_the_whole_set(self):
        """The skipped count must describe every reference for the address, not
        just the ones that landed on the requested page."""
        refs = iter([stack_ref(), memory_ref(0x1000), memory_ref(0x2000), register_ref()])
        items, skipped = collect_xrefs_from(refs, _to_address)
        assert len(items) == 2
        assert skipped == 2

        # A one-item page still reports both skipped refs.
        page = paginate_iter(items, 0, 1)
        assert [i["to_address"] for i in page["items"]] == ["0x1000"]
        assert page["total"] == 2
        assert page["has_more"] is True
        result = XrefsFromResult(**page, skipped_non_memory=skipped)
        assert result.skipped_non_memory == 2
        assert result.total == 2
        assert result.has_more is True


class TestXrefsFromResult:
    def test_skipped_non_memory_defaults_to_zero(self):
        result = XrefsFromResult(items=[], total=0, offset=0, limit=100, has_more=False)
        assert result.skipped_non_memory == 0

    def test_field_is_documented(self):
        field = XrefsFromResult.model_fields["skipped_non_memory"]
        assert field.description
        assert "stack" in field.description.lower()

    def test_field_description_says_external_references_are_kept(self):
        """Only stack, register and constant targets are skipped; a reference to
        an imported symbol stays in ``items`` with an ``EXTERNAL:`` address
        (#43).  The description must say so rather than list EXTERNAL among
        the omissions."""
        desc = XrefsFromResult.model_fields["skipped_non_memory"].description
        assert "kept" in desc.lower()
        assert "external" in desc.lower()


class TestSwitchesSharesTheFilter:
    def test_switches_imports_the_same_predicate(self):
        """``get_switch_info`` formats ``ref.getToAddress().getOffset()`` too, so
        it must reuse this predicate rather than duplicate it."""
        assert switches_mod.is_memory_reference is is_memory_reference


GHIDRA_TOOLS_DIR = (
    pathlib.Path(__file__).resolve().parent.parent
    / "packages"
    / "re-mcp-ghidra"
    / "src"
    / "re_mcp_ghidra"
    / "tools"
)


def _calls_in(module: str, func_name: str) -> set[str]:
    """Names of every function called inside *func_name*'s own body.

    A tool body is nested in ``register(mcp)`` and closes over the session, so
    it cannot be imported and called; the tests above reach only the helpers it
    is supposed to use.  Parsing the one function that must do the filtering
    (same ``ast`` approach as ``test_ghidra_tools_pure.py``) closes the gap:
    dropping the filter from the body would leave the helper tests passing but
    fail here.  The search is scoped to a single ``FunctionDef`` so an
    occurrence elsewhere in the module -- the import line, or a sibling tool --
    cannot satisfy the assertion.  Nested functions count: ``list_switches``
    does its work inside a ``_gen()`` generator.
    """
    tree = ast.parse((GHIDRA_TOOLS_DIR / module).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            return {
                call.func.id if isinstance(call.func, ast.Name) else call.func.attr
                for call in ast.walk(node)
                if isinstance(call, ast.Call) and isinstance(call.func, (ast.Name, ast.Attribute))
            }
    raise AssertionError(f"{func_name}() not found in {module}")


class TestSwitchCountsAgree:
    """#30: ``list_switches`` counted raw references while ``get_switch_info``
    filtered them, so one switch instruction reported two different
    ``num_cases``.  Both now apply the same predicate."""

    def test_list_switches_counts_only_memory_references(self):
        assert "is_memory_reference" in _calls_in("switches.py", "list_switches")

    def test_get_switch_info_uses_the_same_predicate(self):
        assert "is_memory_reference" in _calls_in("switches.py", "get_switch_info")

    def test_the_predicate_they_share_drops_non_memory_targets(self):
        """What both counts exclude: the reference kinds a jump table cannot
        have as a case target."""
        refs = [memory_ref(0x1000), stack_ref(), register_ref(), external_ref(), memory_ref(0x2000)]
        assert [r for r in refs if is_memory_reference(r)] == [refs[0], refs[4]]


class TestFilterIsAppliedInTheToolBodies:
    """Every other test here exercises the helpers directly.  Removing the call
    to them from a tool body -- leaving the helpers and the import in place --
    would restore the #30 bug with all of those still green."""

    def test_get_xrefs_from_calls_the_collector(self):
        assert "collect_xrefs_from" in _calls_in("xrefs.py", "get_xrefs_from")

    def test_get_switch_info_calls_the_predicate(self):
        assert "is_memory_reference" in _calls_in("switches.py", "get_switch_info")

    def test_list_switches_calls_the_predicate(self):
        assert "is_memory_reference" in _calls_in("switches.py", "list_switches")

    def test_the_scan_is_scoped_to_the_named_function(self):
        """``get_xrefs_to`` reads ``getFromAddress()`` and needs no filter, so it
        must come back clean -- if it did not, the assertions above would be
        satisfied by the module's import line rather than by the tool."""
        called = _calls_in("xrefs.py", "get_xrefs_to")
        assert "collect_xrefs_from" not in called
        assert "is_memory_reference" not in called

    def test_a_missing_function_is_an_error_not_an_empty_set(self):
        with pytest.raises(AssertionError):
            _calls_in("xrefs.py", "no_such_tool")
