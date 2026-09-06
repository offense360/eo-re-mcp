# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Unit tests for EXTERNAL-space rendering (#43) — no Ghidra required.

An imported symbol lives in Ghidra's artificial ``EXTERNAL`` address space,
where the offset is a slot index (``free`` sits at ``EXTERNAL:0xb0``).
``get_call_graph`` and ``get_imports`` printed that offset as if it were a
memory address and ``get_xrefs_from`` dropped the reference altogether.  The
helpers under test render such an address by its qualified symbol name and
carry the memory address of the import's thunk so callers can still be found.

The fakes are shaped like ``ghidra.program.model.{address,symbol,listing}``
and cover only the calls the helpers make.
"""

from __future__ import annotations

import ast
import pathlib

from re_mcp_ghidra import helpers as helpers_mod
from re_mcp_ghidra.helpers import describe_external, is_external_address
from re_mcp_ghidra.tools.imports_exports import ImportItem
from re_mcp_ghidra.tools.xrefs import (
    CallGraphEntry,
    XrefFrom,
    XrefsFromResult,
    external_callee,
    is_renderable_reference,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
GHIDRA_PKG = REPO_ROOT / "packages" / "re-mcp-ghidra" / "src" / "re_mcp_ghidra"
GHIDRA_TOOLS_DIR = GHIDRA_PKG / "tools"
DOCS_TOOLS_MD = REPO_ROOT / "docs" / "tools.md"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeAddr:
    def __init__(self, offset: int, *, external: bool = False) -> None:
        self.offset, self.external = offset, external

    def getOffset(self) -> int:
        return self.offset

    def isExternalAddress(self) -> bool:
        return self.external

    def isMemoryAddress(self) -> bool:
        return not self.external

    def __str__(self) -> str:
        return f"EXTERNAL:{self.offset:08x}" if self.external else f"{self.offset:08x}"


class FakeSymbol:
    def __init__(self, name: str, qualified: str) -> None:
        self._name, self._qualified = name, qualified

    def getName(self, include_namespace: bool = False) -> str:
        return self._qualified if include_namespace else self._name


class FakeFunction:
    def __init__(
        self,
        name: str,
        entry: FakeAddr,
        *,
        external: bool = False,
        thunked: FakeFunction | None = None,
        thunk_addrs: list[FakeAddr] | None = None,
    ) -> None:
        self._name, self._entry = name, entry
        self._external, self._thunked, self._thunk_addrs = external, thunked, thunk_addrs

    def getName(self) -> str:
        return self._name

    def getEntryPoint(self) -> FakeAddr:
        return self._entry

    def isExternal(self) -> bool:
        return self._external

    def isThunk(self) -> bool:
        return self._thunked is not None

    def getThunkedFunction(self, recursive: bool) -> FakeFunction | None:
        """``Function.getThunkedFunction(true)`` follows the chain to its end."""
        if not recursive or self._thunked is None:
            return self._thunked
        f = self._thunked
        while f._thunked is not None:
            f = f._thunked
        return f

    def getFunctionThunkAddresses(self, recursive: bool):
        """``null`` (Java) when no thunk points at this function."""
        return self._thunk_addrs


class FakeExtLoc:
    def __init__(self, library: str, function: FakeFunction | None) -> None:
        self._library, self._function = library, function

    def getLibraryName(self) -> str:
        return self._library

    def isFunction(self) -> bool:
        return self._function is not None

    def getFunction(self) -> FakeFunction | None:
        return self._function


class FakeProgram:
    def __init__(self, entries: dict[FakeAddr, tuple[FakeSymbol, FakeExtLoc | None]]) -> None:
        self._entries = entries

    def getSymbolTable(self):
        return self

    def getExternalManager(self):
        return self

    def getPrimarySymbol(self, addr: FakeAddr) -> FakeSymbol | None:
        entry = self._entries.get(addr)
        return entry[0] if entry else None

    def getExternalLocation(self, sym: FakeSymbol) -> FakeExtLoc | None:
        for symbol, loc in self._entries.values():
            if symbol is sym:
                return loc
        return None


# Measured on curl.exe / curl-elf with Ghidra 12.1.2 (instr-43-45.md §0).
FREE_EXT = FakeAddr(0xB0, external=True)
FREE_THUNK = FakeAddr(0x140004210)
GETSOCKNAME_EXT = FakeAddr(0x8, external=True)
FTELL_EXT = FakeAddr(0x1, external=True)
FTELL_PLT = FakeAddr(0x149000)
NO_SYMBOL_EXT = FakeAddr(0xB0, external=True)

FREE_FUNC = FakeFunction("free", FREE_EXT, external=True, thunk_addrs=[FREE_THUNK])
GETSOCKNAME_FUNC = FakeFunction("getsockname", GETSOCKNAME_EXT, external=True, thunk_addrs=[])
FTELL_FUNC = FakeFunction("ftell", FTELL_EXT, external=True, thunk_addrs=[FTELL_PLT])
NULL_THUNKS_FUNC = FakeFunction("nullthunks", FakeAddr(0x7, external=True), external=True)

FREE_SYM = FakeSymbol("free", "API-MS-WIN-CRT-HEAP-L1-1-0.DLL::free")
GETSOCKNAME_SYM = FakeSymbol("getsockname", "WS2_32.DLL::getsockname")
FTELL_SYM = FakeSymbol("ftell", "<EXTERNAL>::ftell")
NULL_THUNKS_SYM = FakeSymbol("nullthunks", "LIB.DLL::nullthunks")
DATA_SYM = FakeSymbol("_acmdln", "API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL::_acmdln")
DATA_EXT = FakeAddr(0x40, external=True)

PROGRAM = FakeProgram(
    {
        FREE_EXT: (FREE_SYM, FakeExtLoc("API-MS-WIN-CRT-HEAP-L1-1-0.DLL", FREE_FUNC)),
        GETSOCKNAME_EXT: (GETSOCKNAME_SYM, FakeExtLoc("WS2_32.DLL", GETSOCKNAME_FUNC)),
        FTELL_EXT: (FTELL_SYM, FakeExtLoc("<EXTERNAL>", FTELL_FUNC)),
        NULL_THUNKS_FUNC.getEntryPoint(): (
            NULL_THUNKS_SYM,
            FakeExtLoc("LIB.DLL", NULL_THUNKS_FUNC),
        ),
        DATA_EXT: (DATA_SYM, FakeExtLoc("API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL", None)),
    }
)


# ---------------------------------------------------------------------------
# describe_external
# ---------------------------------------------------------------------------


class TestDescribeExternal:
    def test_pe_import_with_a_thunk(self):
        assert describe_external(PROGRAM, FREE_EXT) == {
            "address": "EXTERNAL:API-MS-WIN-CRT-HEAP-L1-1-0.DLL::free",
            "symbol": "free",
            "library": "API-MS-WIN-CRT-HEAP-L1-1-0.DLL",
            "thunk_address": "0x140004210",
        }

    def test_pe_ordinal_import_without_a_thunk(self):
        """``getsockname`` is only reached through its IAT slot: the thunk list
        is empty and there is no memory address to offer."""
        assert describe_external(PROGRAM, GETSOCKNAME_EXT) == {
            "address": "EXTERNAL:WS2_32.DLL::getsockname",
            "symbol": "getsockname",
            "library": "WS2_32.DLL",
            "thunk_address": None,
        }

    def test_elf_import_thunk_is_the_plt_entry(self):
        assert describe_external(PROGRAM, FTELL_EXT) == {
            "address": "EXTERNAL:<EXTERNAL>::ftell",
            "symbol": "ftell",
            "library": "<EXTERNAL>",
            "thunk_address": "0x149000",
        }

    def test_java_null_thunk_list_is_no_thunk(self):
        """``getFunctionThunkAddresses`` returns ``null`` rather than an empty
        array when nothing thunks the function; ``len(None)`` must not happen."""
        ext = describe_external(PROGRAM, NULL_THUNKS_FUNC.getEntryPoint())
        assert ext["thunk_address"] is None
        assert ext["address"] == "EXTERNAL:LIB.DLL::nullthunks"

    def test_data_import_has_a_library_but_no_thunk(self):
        assert describe_external(PROGRAM, DATA_EXT) == {
            "address": "EXTERNAL:API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL::_acmdln",
            "symbol": "_acmdln",
            "library": "API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL",
            "thunk_address": None,
        }

    def test_address_without_a_symbol_falls_back_to_the_slot_offset(self):
        assert describe_external(FakeProgram({}), NO_SYMBOL_EXT) == {
            "address": "EXTERNAL:0xb0",
            "symbol": "",
            "library": "",
            "thunk_address": None,
        }

    def test_helpers_export_both_names(self):
        assert "describe_external" in helpers_mod.__all__
        assert "is_external_address" in helpers_mod.__all__


class TestIsExternalAddress:
    def test_none_is_not_external(self):
        assert is_external_address(None) is False

    def test_external_space_address(self):
        assert is_external_address(FREE_EXT) is True

    def test_memory_address(self):
        assert is_external_address(FREE_THUNK) is False


# ---------------------------------------------------------------------------
# external_callee — what get_call_graph treats as "an import"
# ---------------------------------------------------------------------------


class TestExternalCallee:
    def test_external_function_is_itself(self):
        assert external_callee(FREE_FUNC) is FREE_FUNC

    def test_thunk_to_an_external_resolves_to_the_external(self):
        """PE ``free``: the call graph sees the thunk at ``0x140004210`` *and*
        the external ``EXTERNAL:0xb0``.  Both must collapse onto the external."""
        thunk = FakeFunction("free", FREE_THUNK, thunked=FREE_FUNC)
        assert external_callee(thunk) is FREE_FUNC

    def test_chain_of_thunks_is_followed_to_the_end(self):
        middle = FakeFunction("free", FakeAddr(0x140009000), thunked=FREE_FUNC)
        outer = FakeFunction("free", FREE_THUNK, thunked=middle)
        assert external_callee(outer) is FREE_FUNC

    def test_internal_function_is_none(self):
        assert external_callee(FakeFunction("FUN_14001a400", FakeAddr(0x14001A400))) is None

    def test_internal_thunk_is_none(self):
        """``_guard_dispatch_icall`` at ``0x14008F3F0`` has an internal thunk at
        ``0x14008F410``; neither side is an import and both stay as they are."""
        target = FakeFunction("_guard_dispatch_icall", FakeAddr(0x14008F3F0))
        thunk = FakeFunction("_guard_dispatch_icall", FakeAddr(0x14008F410), thunked=target)
        assert external_callee(thunk) is None
        assert external_callee(target) is None

    def test_thunk_without_a_resolvable_target_is_none(self):
        class Dangling(FakeFunction):
            def isThunk(self) -> bool:
                return True

        assert external_callee(Dangling("x", FakeAddr(0x1000))) is None


# ---------------------------------------------------------------------------
# is_renderable_reference — what get_xrefs_from keeps as an item
# ---------------------------------------------------------------------------


class FakeRef:
    def __init__(self, to: FakeAddr | None, *, stack: bool = False, register: bool = False):
        self._to, self._stack, self._register = to, stack, register

    def getToAddress(self) -> FakeAddr | None:
        return self._to

    def isStackReference(self) -> bool:
        return self._stack

    def isRegisterReference(self) -> bool:
        return self._register


class TestIsRenderableReference:
    def test_memory_reference(self):
        assert is_renderable_reference(FakeRef(FakeAddr(0x140091800))) is True

    def test_external_reference(self):
        assert is_renderable_reference(FakeRef(FREE_EXT)) is True

    def test_stack_reference(self):
        assert is_renderable_reference(FakeRef(FakeAddr(0x10), stack=True)) is False

    def test_register_reference(self):
        assert is_renderable_reference(FakeRef(FakeAddr(0x10), register=True)) is False

    def test_no_target(self):
        assert is_renderable_reference(FakeRef(None)) is False


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------


class TestModels:
    def test_xref_from_carries_a_library(self):
        field = XrefFrom.model_fields["library"]
        assert field.default is None
        assert "external" in (field.description or "").lower()

    def test_xref_from_to_address_documents_the_external_form(self):
        desc = XrefFrom.model_fields["to_address"].description or ""
        assert "EXTERNAL:<library>::<name>" in desc

    def test_xref_from_still_builds_without_a_library(self):
        item = XrefFrom(to_address="0x1", to_function="", ref_type="DATA", is_call=False)
        assert item.library is None

    def test_skipped_non_memory_no_longer_claims_external_is_skipped(self):
        desc = (XrefsFromResult.model_fields["skipped_non_memory"].description or "").lower()
        assert "kept" in desc
        assert "external:" in desc

    def test_call_graph_callees_document_external_entries(self):
        desc = (CallGraphEntry.model_fields["callees"].description or "").lower()
        assert "external" in desc
        assert "thunk_address" in desc

    def test_import_item_address_is_the_thunk_and_may_be_null(self):
        field = ImportItem.model_fields["address"]
        assert "thunk" in (field.description or "").lower()
        item = ImportItem(
            module="WS2_32.DLL",
            address=None,
            name="getsockname",
            external_address="EXTERNAL:WS2_32.DLL::getsockname",
        )
        assert item.address is None

    def test_import_item_external_address_documents_the_form(self):
        desc = ImportItem.model_fields["external_address"].description or ""
        assert "EXTERNAL:<library>::<name>" in desc
        assert "get_xrefs_from" in desc


# ---------------------------------------------------------------------------
# The tool bodies must actually use the helpers
# ---------------------------------------------------------------------------


def _calls_in(path: pathlib.Path, func_name: str) -> set[str]:
    """Names called inside *func_name* (nested functions included)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            return {
                call.func.id if isinstance(call.func, ast.Name) else call.func.attr
                for call in ast.walk(node)
                if isinstance(call, ast.Call) and isinstance(call.func, (ast.Name, ast.Attribute))
            }
    raise AssertionError(f"{func_name}() not found in {path.name}")


XREFS_PY = GHIDRA_TOOLS_DIR / "xrefs.py"
IMPORTS_EXPORTS_PY = GHIDRA_TOOLS_DIR / "imports_exports.py"
RESOURCES_PY = GHIDRA_PKG / "resources.py"


class TestToolBodiesUseTheHelpers:
    def test_get_xrefs_from_renders_external_targets(self):
        assert "describe_external" in _calls_in(XREFS_PY, "_render")

    def test_collect_xrefs_from_uses_the_wider_predicate(self):
        called = _calls_in(XREFS_PY, "collect_xrefs_from")
        assert "is_renderable_reference" in called
        assert "is_memory_reference" not in called

    def test_call_graph_collapses_external_callees(self):
        called = _calls_in(XREFS_PY, "_build_call_graph")
        assert "external_callee" in called
        assert "describe_external" in called

    def test_call_graph_visited_keys_include_the_address_space(self):
        """An EXTERNAL offset must not collide with a memory offset."""
        source = XREFS_PY.read_text(encoding="utf-8")
        _, _, body = source.partition("def _build_call_graph(")
        assert "getOffset() not in visited" not in body
        assert "key = addr.getOffset()" not in body

    def test_get_imports_uses_describe_external(self):
        assert "describe_external" in _calls_in(IMPORTS_EXPORTS_PY, "get_imports")

    def test_imports_resource_uses_describe_external_not_get_address(self):
        called = _calls_in(RESOURCES_PY, "_iter_imports")
        assert "describe_external" in called
        assert "getAddress" not in called


class TestDocs:
    def _row(self, tool: str) -> str:
        rows = [
            line
            for line in DOCS_TOOLS_MD.read_text(encoding="utf-8").splitlines()
            if line.startswith(f"| `{tool}`")
        ]
        assert len(rows) == 1, tool
        return rows[0]

    def test_get_xrefs_from(self):
        row = self._row("get_xrefs_from")
        assert "EXTERNAL:" in row
        assert "yields no item" not in row

    def test_get_call_graph(self):
        row = self._row("get_call_graph").lower()
        assert "external" in row
        assert "once" in row

    def test_get_imports(self):
        row = self._row("get_imports")
        assert "thunk" in row.lower()
        assert "external_address" in row
