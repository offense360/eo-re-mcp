# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Pure unit tests for ``re_mcp_ghidra.tools.database`` helpers.

The tool bodies live inside ``register()`` closures and cannot be called
directly, so the logic under test is extracted into module-level functions
and exercised here with fake JPype-shaped objects (same style as
``tests/test_ghidra_helpers_pure.py``).  ``re_mcp_ghidra.tools.database``
only touches Ghidra classes at call time, so the module imports fine in the
plain test venv.
"""

from __future__ import annotations

import pathlib

from re_mcp_ghidra.tools.analysis import AnalysisCompleteResult, analysis_bounds
from re_mcp_ghidra.tools.database import (
    DatabaseInfoResult,
    OpenDatabaseResult,
    count_functions,
    database_info_paths,
    entry_points,
    loaded_memory_bounds,
)

GHIDRA_TOOLS_DIR = (
    pathlib.Path(__file__).resolve().parent.parent
    / "packages"
    / "re-mcp-ghidra"
    / "src"
    / "re_mcp_ghidra"
    / "tools"
)
DATABASE_PY = GHIDRA_TOOLS_DIR / "database.py"
ANALYSIS_PY = GHIDRA_TOOLS_DIR / "analysis.py"
FUNCTIONS_PY = GHIDRA_TOOLS_DIR / "functions.py"
IMPORTS_EXPORTS_PY = GHIDRA_TOOLS_DIR / "imports_exports.py"
RESOURCES_PY = GHIDRA_TOOLS_DIR.parent / "resources.py"
DOCS_TOOLS_MD = pathlib.Path(__file__).resolve().parent.parent / "docs" / "tools.md"


# ---------------------------------------------------------------------------
# Fakes shaped like ghidra.program.model.address / mem.MemoryBlock
# ---------------------------------------------------------------------------


class FakeSpace:
    def __init__(self, name: str, *, loaded: bool = True) -> None:
        self.name, self.loaded = name, loaded

    def isLoadedMemorySpace(self) -> bool:
        return self.loaded

    def __repr__(self) -> str:
        return f"<space {self.name}>"


RAM = FakeSpace("ram")
RAM2 = FakeSpace("ram2")
RAM3 = FakeSpace("ram3")
OTHER = FakeSpace("OTHER", loaded=False)


class FakeAddr:
    def __init__(self, offset: int, space: FakeSpace = RAM) -> None:
        self.offset, self.space = offset, space

    def getOffset(self) -> int:
        return self.offset

    def getAddressSpace(self) -> FakeSpace:
        return self.space

    def isLoadedMemoryAddress(self) -> bool:
        return self.space.isLoadedMemorySpace()

    def compareTo(self, other: FakeAddr) -> int:
        """Ghidra orders by address space first, then by offset."""
        mine, theirs = (self.space.name, self.offset), (other.space.name, other.offset)
        return (mine > theirs) - (mine < theirs)

    def __repr__(self) -> str:
        return f"{self.space.name}:0x{self.offset:x}"


class FakeBlock:
    def __init__(
        self,
        start: int,
        end: int,
        space: FakeSpace = RAM,
        *,
        artificial: bool = False,
        end_space: FakeSpace | None = None,
    ) -> None:
        """*end_space* exists only to build the impossible block of
        ``test_a_block_whose_end_is_in_another_space_cannot_contribute``; a real
        ``MemoryBlock`` is one contiguous range inside a single address space."""
        self.start = FakeAddr(start, space)
        self.end = FakeAddr(end, end_space or space)
        self.artificial = artificial

    def getStart(self) -> FakeAddr:
        return self.start

    def getEnd(self) -> FakeAddr:
        return self.end

    def isArtificial(self) -> bool:
        """``MemoryBlock.isArtificial()`` — set on blocks a loader or analyzer
        fabricated, which "do not exist in the same form within a
        running/loaded process state" (``MemoryBlock.java:210-218``)."""
        return self.artificial

    def isLoaded(self) -> bool:
        """Modelled on the *implementation*, not the interface javadoc.

        ``MemoryBlockDB.isLoaded()`` is literally
        ``startAddress.getAddressSpace().isLoadedMemorySpace()``
        (``MemoryBlockDB.java:433-435``), so it is redundant with
        ``Address.isLoadedMemoryAddress()`` and cannot single out the header or
        analysis-generated blocks that ``MemoryBlock.java:370-374`` advertises.
        Keeping the fake honest stops a filter that leans on it from passing
        here while being a no-op on a real database.
        """
        return self.start.isLoadedMemoryAddress()


class FakeMemory:
    def __init__(self, *blocks: FakeBlock) -> None:
        self.blocks = blocks

    def getBlocks(self):
        return list(self.blocks)


def _offsets(bounds) -> tuple:
    lo, hi = bounds
    return (None if lo is None else lo.getOffset(), None if hi is None else hi.getOffset())


# ---------------------------------------------------------------------------
# Issue #27 — min/max_address must come from loaded memory only
# ---------------------------------------------------------------------------


class TestLoadedMemoryBounds:
    def test_other_space_blocks_are_excluded(self):
        """The ELF loader puts ``_elfSectionHeaders`` in a non-loaded space over
        OTHER; its offsets must never leak into min/max_address.  (PE
        ``Headers`` is *not* one of these - it sits in the default ram space,
        as ``test_pe_artificial_block_in_the_default_space_is_excluded`` shows.)
        """
        mem = FakeMemory(
            FakeBlock(0x100000, 0x1FFFFF),
            FakeBlock(0x200000, 0x2FFFFF),
            FakeBlock(0x0, 0x77F, OTHER),
        )
        assert _offsets(loaded_memory_bounds(mem)) == (0x100000, 0x2FFFFF)

    def test_no_blocks_at_all(self):
        assert loaded_memory_bounds(FakeMemory()) == (None, None)

    def test_only_an_unloaded_block(self):
        assert loaded_memory_bounds(FakeMemory(FakeBlock(0x0, 0x77F, OTHER))) == (None, None)

    def test_default_space_wins_when_several_loaded_spaces_exist(self):
        mem = FakeMemory(
            FakeBlock(0x100000, 0x1FFFFF),
            FakeBlock(0x10, 0x20, RAM2),
            FakeBlock(0x300000, 0x3FFFFF),
        )
        assert _offsets(loaded_memory_bounds(mem, RAM)) == (0x100000, 0x3FFFFF)
        assert _offsets(loaded_memory_bounds(mem, RAM2)) == (0x10, 0x20)

    def test_default_space_ignored_when_it_has_no_loaded_blocks(self):
        """A default space with no blocks must not turn into ``(None, None)``."""
        mem = FakeMemory(FakeBlock(0x100000, 0x1FFFFF, RAM2))
        assert _offsets(loaded_memory_bounds(mem, RAM)) == (0x100000, 0x1FFFFF)

    def test_pe_artificial_block_in_the_default_space_is_excluded(self):
        """All 8 blocks of the real analyzed curl.exe (PE x64, Ghidra 12.1.2).

        Every one sits in the default ``ram`` space and every one has
        ``isLoaded() == True``, so neither an address-space test nor
        ``MemoryBlock.isLoaded()`` separates them.  ``tdb`` is the Thread
        Environment Block that the Windows analyzer fabricates after import
        (``ThreadEnvironmentBlock.java:75`` names it; ``:725``/``:810`` call
        ``setArtificial(true)``), and it is the only one of the eight whose
        observed flags carry ``ARTIFICIAL`` (``0x16`` =
        ``ARTIFICIAL|READ|WRITE``, ``MemoryBlock.java:51-55``).  Before the fix
        it supplied ``max_address 0xFF0000184F``.

        ``Headers`` is *not* artificial — it is real image content — so it stays
        and pins ``min_address`` to the image base.
        """
        mem = FakeMemory(
            FakeBlock(0x140000000, 0x1400003FF),  # Headers
            FakeBlock(0x140001000, 0x1400901FF),  # .text
            FakeBlock(0x140091000, 0x1400BFBFF),  # .rdata
            FakeBlock(0x1400C0000, 0x1400C1F9F),  # .data
            FakeBlock(0x1400C2000, 0x1400C6BFF),  # .pdata
            FakeBlock(0x1400C7000, 0x1400C75FF),  # .rsrc
            FakeBlock(0x1400C8000, 0x1400C95FF),  # .reloc
            FakeBlock(0xFF00000000, 0xFF0000184F, artificial=True),  # tdb
        )
        assert _offsets(loaded_memory_bounds(mem, RAM)) == (0x140000000, 0x1400C95FF)

    def test_elf_external_and_overlay_blocks_are_excluded(self):
        """The real analyzed curl-elf (ELF x64, Ghidra 12.1.2), abridged to the
        blocks that decide the bounds.

        Its 29 ``ram`` blocks span ``0x100000``..``0x148607``.  ``.bss`` ends the
        image and is *uninitialized*, so an "initialized" filter would truncate
        it.  ``EXTERNAL`` is the synthetic import block, made artificial by
        ``MemoryBlockUtils.java:409``.  The three overlay blocks live in their
        own non-loaded address spaces.
        """
        gnu_debuglink = FakeSpace(".gnu_debuglink", loaded=False)
        shstrtab = FakeSpace(".shstrtab", loaded=False)
        section_headers = FakeSpace("_elfSectionHeaders", loaded=False)
        mem = FakeMemory(
            FakeBlock(0x100000, 0x100317),  # segment_2.1
            FakeBlock(0x10C120, 0x126E7C),  # .text
            FakeBlock(0x148000, 0x14806F),  # .data
            FakeBlock(0x148080, 0x148607),  # .bss, uninitialized
            FakeBlock(0x149000, 0x149477, artificial=True),  # EXTERNAL
            FakeBlock(0x0, 0x33, gnu_debuglink),
            FakeBlock(0x0, 0x11C, shstrtab),
            FakeBlock(0x0, 0x77F, section_headers),
        )
        assert _offsets(loaded_memory_bounds(mem, RAM)) == (0x100000, 0x148607)

    def test_falls_back_to_loaded_addresses_when_every_block_is_artificial(self):
        """Bounded fallback: a program made entirely of fabricated blocks still
        reports its extent rather than ``0x0``/``0x0``."""
        mem = FakeMemory(
            FakeBlock(0x1000, 0x1FFF, artificial=True),
            FakeBlock(0x3000, 0x3FFF, artificial=True),
        )
        assert _offsets(loaded_memory_bounds(mem, RAM)) == (0x1000, 0x3FFF)

    def test_fallback_still_yields_nothing_for_unloaded_spaces(self):
        mem = FakeMemory(FakeBlock(0x0, 0x77F, OTHER, artificial=True))
        assert loaded_memory_bounds(mem, RAM) == (None, None)


class TestBoundsComeFromASingleAddressSpace:
    """``format_address`` serialises ``getOffset()`` only, so a pair drawn from
    two different spaces re-creates the #27 ``min > max`` inversion."""

    def _assert_same_space_and_ordered(self, bounds) -> None:
        lo, hi = bounds
        assert lo is not None and hi is not None
        assert lo.getAddressSpace() is hi.getAddressSpace()
        assert lo.getOffset() <= hi.getOffset()

    def test_two_non_default_loaded_spaces_do_not_mix(self):
        mem = FakeMemory(
            FakeBlock(0x100000, 0x1FFFFF, RAM2),
            FakeBlock(0x10, 0x20, RAM3),
        )
        bounds = loaded_memory_bounds(mem, RAM)  # default space holds no block
        self._assert_same_space_and_ordered(bounds)
        assert _offsets(bounds) == (0x100000, 0x1FFFFF)

    def test_two_non_default_loaded_spaces_without_a_default_space(self):
        mem = FakeMemory(
            FakeBlock(0x10, 0x20, RAM3),
            FakeBlock(0x100000, 0x1FFFFF, RAM2),
        )
        bounds = loaded_memory_bounds(mem)
        self._assert_same_space_and_ordered(bounds)
        assert _offsets(bounds) == (0x100000, 0x1FFFFF)

    def test_block_order_does_not_change_the_chosen_space(self):
        blocks = (
            FakeBlock(0x10, 0x20, RAM3),
            FakeBlock(0x100000, 0x1FFFFF, RAM2),
        )
        forward = loaded_memory_bounds(FakeMemory(*blocks), RAM)
        backward = loaded_memory_bounds(FakeMemory(*reversed(blocks)), RAM)
        assert _offsets(forward) == _offsets(backward)

    def test_fallback_path_is_also_single_space(self):
        """The all-artificial fallback must not reintroduce the inversion."""
        mem = FakeMemory(
            FakeBlock(0x100000, 0x1FFFFF, RAM2, artificial=True),
            FakeBlock(0x10, 0x20, RAM3, artificial=True),
        )
        bounds = loaded_memory_bounds(mem, RAM)
        self._assert_same_space_and_ordered(bounds)

    def test_a_block_whose_end_is_in_another_space_cannot_contribute(self):
        """Defensive invariant, no known reachable trigger.

        Qualifying blocks are picked by ``getStart()``'s space, so on its own
        that leaves ``getEnd()``'s space unchecked and a block could in
        principle hand back a ``max`` from a different space than ``min`` -
        exactly the #27 inversion, since only ``getOffset()`` is serialised.  A
        real ``MemoryBlock`` is a contiguous range inside ONE address space, so
        this block cannot occur in Ghidra; the guard is cheap and the test pins
        it.
        """
        mem = FakeMemory(
            FakeBlock(0x100000, 0x1FFFFF),
            FakeBlock(0x200000, 0x10, end_space=RAM2),  # impossible: start ram, end ram2
        )
        bounds = loaded_memory_bounds(mem, RAM)
        self._assert_same_space_and_ordered(bounds)
        assert _offsets(bounds) == (0x100000, 0x1FFFFF)


class TestGetDatabaseInfoUsesLoadedBounds:
    def test_field_descriptions_cover_the_new_loaded_block_filter(self):
        fields = DatabaseInfoResult.model_fields
        for name in ("min_address", "max_address"):
            desc = (fields[name].description or "").lower()
            assert "one address space" in desc
            assert "tdb" in desc

    def test_the_block_filter_uses_is_artificial_not_is_loaded(self):
        """``MemoryBlockDB.isLoaded()`` is exactly
        ``startAddress.getAddressSpace().isLoadedMemorySpace()``
        (``MemoryBlockDB.java:433-435``), so it duplicates the address test and
        is a no-op against ``tdb``.  ``isArtificial()`` is the real filter."""
        source = DATABASE_PY.read_text(encoding="utf-8")
        assert "isArtificial()" in source
        assert "isLoadedMemoryAddress()" in source
        assert "b.isLoaded()" not in source

    def test_memory_min_max_address_no_longer_used(self):
        """``Memory.getMinAddress()/getMaxAddress()`` span every address space,
        and ``getOffset()`` drops the space — so they must be gone (#27)."""
        source = DATABASE_PY.read_text(encoding="utf-8")
        assert "mem.getMinAddress()" not in source
        assert "mem.getMaxAddress()" not in source
        assert "loaded_memory_bounds(" in source

    def test_field_descriptions_explain_the_exclusion(self):
        fields = DatabaseInfoResult.model_fields
        for name, word in (("min_address", "lowest"), ("max_address", "highest")):
            desc = (fields[name].description or "").lower()
            assert word in desc
            assert "loaded memory" in desc
            assert "default address space" in desc
            assert "elf section headers" in desc
            # PE 'Headers' is real image content and is *kept* - saying
            # otherwise is the mistake the isLoaded() story led to.
            assert "pe headers are real image content and are kept" in desc
            # ...and the filter that actually excludes 'tdb'/'EXTERNAL'.
            assert "artificial" in desc
            assert "external" in desc

    def test_field_descriptions_document_the_artificial_only_fallback(self):
        """The contract must not claim artificial blocks are excluded
        unconditionally: when nothing else qualifies they are what is left, and
        ``test_falls_back_to_loaded_addresses_when_every_block_is_artificial``
        pins that behaviour."""
        fields = DatabaseInfoResult.model_fields
        for name in ("min_address", "max_address"):
            desc = (fields[name].description or "").lower()
            assert "fall back" in desc
            assert "artificial ones included" in desc


# ---------------------------------------------------------------------------
# Issue #29 — function_count must match list_functions.total
# ---------------------------------------------------------------------------


class FakeFunctionManager:
    """``FunctionManager.getFunctionCount()`` counts external functions too,
    while ``getFunctions(True)`` — what ``list_functions`` iterates — does not."""

    def __init__(self, total: int, external: int) -> None:
        self.total, self.external = total, external

    def getFunctionCount(self) -> int:
        return self.total

    def getExternalFunctions(self):
        return iter([f"extern_{i}" for i in range(self.external)])


class TestCountFunctions:
    def test_pe_case_matches_list_functions_total(self):
        """Real curl.exe: get_database_info said 2006, list_functions said 1775."""
        assert count_functions(FakeFunctionManager(2006, 231)) == (1775, 231)

    def test_elf_case(self):
        """Real ELF: 543 reported vs 403 listed."""
        assert count_functions(FakeFunctionManager(543, 140)) == (403, 140)

    def test_no_external_functions(self):
        assert count_functions(FakeFunctionManager(12, 0)) == (12, 0)

    def test_empty_program(self):
        assert count_functions(FakeFunctionManager(0, 0)) == (0, 0)

    def test_external_iterable_is_consumed_once(self):
        """``getExternalFunctions()`` returns a one-shot Java iterator."""
        mgr = FakeFunctionManager(5, 2)
        assert count_functions(mgr) == (3, 2)


class TestExternalFunctionCountIsReported:
    def test_both_result_models_expose_the_field(self):
        for model in (DatabaseInfoResult, OpenDatabaseResult):
            field = model.model_fields["external_function_count"]
            assert field.default == 0
            desc = (field.description or "").lower()
            assert "external" in desc
            assert "not included in function_count" in desc
            assert "list_functions" in desc

    def test_raw_get_function_count_is_gone_from_the_tool_bodies(self):
        source = DATABASE_PY.read_text(encoding="utf-8")
        _, marker, tool_bodies = source.partition("def register(")
        assert marker, "register() not found - parser regression?"
        assert "getFunctionCount()" not in tool_bodies
        # open_database + get_database_info
        assert tool_bodies.count("count_functions(") == 2

    def test_analysis_uses_the_shared_counter(self):
        source = ANALYSIS_PY.read_text(encoding="utf-8")
        assert "count_functions" in source
        assert "func_mgr.getFunctionCount()" not in source

    def test_list_functions_docstring_points_at_the_new_field(self):
        source = FUNCTIONS_PY.read_text(encoding="utf-8")
        assert (
            "External functions are not listed; see get_database_info.external_function_count."
            in source
        )


# ---------------------------------------------------------------------------
# Issue #31 — file_path must be the OS path
# ---------------------------------------------------------------------------


class TestDatabaseInfoPaths:
    def test_session_path_wins_over_the_importer_path(self):
        """open_database / list_databases return the OS path; get_database_info
        returned Ghidra's normalised '/C:/...' form instead (#31)."""
        assert database_info_paths(r"C:\x\curl.exe", "/C:/x/curl.exe") == (
            r"C:\x\curl.exe",
            "/C:/x/curl.exe",
        )

    def test_importer_path_is_the_fallback_when_the_session_has_none(self):
        assert database_info_paths("", "/C:/x/curl.exe") == ("/C:/x/curl.exe", "/C:/x/curl.exe")

    def test_none_inputs_become_empty_strings(self):
        assert database_info_paths(None, None) == ("", "")
        assert database_info_paths("", "") == ("", "")
        assert database_info_paths(None, "/opt/bin/ls") == ("/opt/bin/ls", "/opt/bin/ls")
        assert database_info_paths("/opt/bin/ls", None) == ("/opt/bin/ls", "")

    def test_posix_paths_are_returned_verbatim(self):
        """On POSIX the two agree; nothing must be rewritten either way."""
        assert database_info_paths("/opt/bin/ls", "/opt/bin/ls") == ("/opt/bin/ls", "/opt/bin/ls")


class TestExecutablePathIsExposed:
    def test_field_documents_the_importer_normalisation(self):
        field = DatabaseInfoResult.model_fields["executable_path"]
        assert field.default == ""
        desc = (field.description or "").lower()
        assert "importer" in desc
        assert "normalised" in desc

    def test_get_database_info_uses_the_helper(self):
        source = DATABASE_PY.read_text(encoding="utf-8")
        _, marker, tool_bodies = source.partition("def register(")
        assert marker, "register() not found - parser regression?"
        assert "database_info_paths(" in tool_bodies
        assert "program.getExecutablePath() or session.current_path" not in tool_bodies


# ---------------------------------------------------------------------------
# analyze_database bounds (#44) - same definition as get_database_info (#27)
# ---------------------------------------------------------------------------


class FakeAddressFactory:
    def __init__(self, default_space: FakeSpace) -> None:
        self._space = default_space

    def getDefaultAddressSpace(self) -> FakeSpace:
        return self._space


class FakeProgram:
    """Just enough ``Program`` for ``analysis_bounds``."""

    def __init__(self, memory: FakeMemory, default_space: FakeSpace = RAM) -> None:
        self._memory = memory
        self._factory = FakeAddressFactory(default_space)

    def getMemory(self) -> FakeMemory:
        return self._memory

    def getAddressFactory(self) -> FakeAddressFactory:
        return self._factory


class TestAnalyzeDatabaseUsesLoadedBounds:
    """``analyze_database`` (and so the first ``wait_for_analysis``) must report
    the bounds ``get_database_info`` reports, not ``Program.getMin/MaxAddress()``
    (#44): PE ``0x1400C95FF`` instead of the ``tdb`` end ``0xFF0000184F``, ELF
    ``0x148607`` instead of the section-header overlay end ``0x77F``."""

    def test_program_min_max_address_no_longer_used(self):
        source = ANALYSIS_PY.read_text(encoding="utf-8")
        assert "getMinAddress(" not in source
        assert "getMaxAddress(" not in source
        assert "loaded_memory_bounds" in source

    def test_pe_bounds_stop_at_reloc_not_tdb(self):
        program = FakeProgram(
            FakeMemory(
                FakeBlock(0x140000000, 0x1400003FF),  # Headers
                FakeBlock(0x140001000, 0x1400901FF),  # .text
                FakeBlock(0x1400C8000, 0x1400C95FF),  # .reloc
                FakeBlock(0xFF00000000, 0xFF0000184F, artificial=True),  # tdb
            )
        )
        assert analysis_bounds(program) == ("0x140000000", "0x1400C95FF")

    def test_elf_bounds_stop_at_bss_not_section_headers(self):
        section_headers = FakeSpace("_elfSectionHeaders", loaded=False)
        program = FakeProgram(
            FakeMemory(
                FakeBlock(0x100000, 0x100317),  # segment_2.1
                FakeBlock(0x148080, 0x148607),  # .bss
                FakeBlock(0x149000, 0x149477, artificial=True),  # EXTERNAL
                FakeBlock(0x0, 0x77F, section_headers),
            )
        )
        assert analysis_bounds(program) == ("0x100000", "0x148607")

    def test_no_usable_block_reports_zero(self):
        assert analysis_bounds(FakeProgram(FakeMemory())) == ("0x0", "0x0")

    def test_bounds_agree_with_get_database_info_definition(self):
        """Whatever ``loaded_memory_bounds`` picks is what ``analysis_bounds``
        formats - the two tools cannot drift apart."""
        mem = FakeMemory(
            FakeBlock(0x10, 0x20, RAM2),
            FakeBlock(0x100000, 0x1FFFFF, RAM2),
        )
        lo, hi = loaded_memory_bounds(mem, RAM)
        assert analysis_bounds(FakeProgram(mem, RAM)) == (
            f"0x{lo.getOffset():X}",
            f"0x{hi.getOffset():X}",
        )

    def test_field_descriptions_point_at_get_database_info(self):
        fields = AnalysisCompleteResult.model_fields
        for name in ("min_address", "max_address"):
            desc = (fields[name].description or "").lower()
            assert "get_database_info" in desc
            assert "one address space" in desc


# ---------------------------------------------------------------------------
# Issue #45 — one definition of "entry point" (an address, per Ghidra's own
# SymbolTable.getExternalEntryPointIterator()) for every tool that counts or
# lists them
# ---------------------------------------------------------------------------


class FakeSymbol:
    def __init__(self, name: str, addr: FakeAddr, sym_type: str) -> None:
        self._name, self._addr, self._type = name, addr, sym_type

    def getName(self) -> str:
        return self._name

    def getAddress(self) -> FakeAddr:
        return self._addr

    def isExternalEntryPoint(self) -> bool:
        return True

    def getSymbolType(self) -> str:
        return self._type


class FakeSymbolTable:
    """``SymbolTable`` narrowed to the entry point API.

    *entries* is ``[(address, names)]``; ``names`` lists every symbol at the
    address, primary first, and ``None`` means the address carries no symbol.
    A second name models the ELF label/function overlap
    (``_DT_INIT`` + ``__DT_INIT``) — a FUNCTION primary plus a LABEL —
    which is what made the symbol-based count come out at 7 for 5 addresses.
    """

    def __init__(self, entries: list[tuple[FakeAddr, list[str] | None]]) -> None:
        self._entries = entries

    def getExternalEntryPointIterator(self):
        return iter(addr for addr, _ in self._entries)

    def getPrimarySymbol(self, addr: FakeAddr) -> FakeSymbol | None:
        for a, names in self._entries:
            if a is addr:
                return FakeSymbol(names[0], addr, "Function") if names else None
        return None

    def getAllSymbols(self, include_dynamic: bool):
        """Old-style enumeration: every symbol, each flagged as an entry point."""
        for addr, names in self._entries:
            for i, name in enumerate(names or []):
                yield FakeSymbol(name, addr, "Function" if i == 0 else "Label")


ELF_ENTRIES: list[tuple[FakeAddr, list[str] | None]] = [
    (FakeAddr(0x10E3A0), ["entry"]),
    (FakeAddr(0x10B000), ["_DT_INIT", "__DT_INIT"]),
    (FakeAddr(0x126E80), ["_DT_FINI", "__DT_FINI"]),
    (FakeAddr(0x10E480), ["_INIT_0"]),
    (FakeAddr(0x10E440), ["_FINI_0"]),
]


class TestEntryPoints:
    def test_elf_counts_addresses_not_symbols(self):
        """5 entry point addresses, 7 entry point symbols: the count is 5 (#45)."""
        st = FakeSymbolTable(ELF_ENTRIES)
        assert sum(1 for s in st.getAllSymbols(True) if s.isExternalEntryPoint()) == 7
        assert len(entry_points(st)) == 5

    def test_elf_names_are_the_primary_symbols_in_iterator_order(self):
        st = FakeSymbolTable(ELF_ENTRIES)
        assert [name for _, name in entry_points(st)] == [
            "entry",
            "_DT_INIT",
            "_DT_FINI",
            "_INIT_0",
            "_FINI_0",
        ]

    def test_returns_the_iterator_address_objects(self):
        st = FakeSymbolTable(ELF_ENTRIES)
        assert [addr for addr, _ in entry_points(st)] == [a for a, _ in ELF_ENTRIES]

    def test_pe_has_one_entry(self):
        st = FakeSymbolTable([(FakeAddr(0x1400049F0), ["entry"])])
        assert [(a.getOffset(), n) for a, n in entry_points(st)] == [(0x1400049F0, "entry")]

    def test_address_without_a_symbol_has_an_empty_name(self):
        st = FakeSymbolTable([(FakeAddr(0x401000), None)])
        assert [(a.getOffset(), n) for a, n in entry_points(st)] == [(0x401000, "")]

    def test_empty_iterator_gives_empty_list(self):
        assert entry_points(FakeSymbolTable([])) == []


def _between(source: str, start: str, end: str | None) -> str:
    _, marker, rest = source.partition(start)
    assert marker, f"{start!r} not found - parser regression?"
    if end is None:
        return rest
    body, _, _ = rest.partition(end)
    return body


class TestEveryEntryPointConsumerUsesTheHelper:
    """The four places that counted or listed entry points each had their own
    predicate (#45).  All of them must now go through ``entry_points()``; the
    symbol-level ``isExternalEntryPoint()`` test survives only where exports
    are enumerated, which is a different concept."""

    def test_get_database_info(self):
        source = DATABASE_PY.read_text(encoding="utf-8")
        tool_bodies = _between(source, "def register(", None)
        assert "isExternalEntryPoint()" not in tool_bodies
        assert tool_bodies.count("entry_points(") == 1

    def test_analyze_database(self):
        source = ANALYSIS_PY.read_text(encoding="utf-8")
        assert "isExternalEntryPoint()" not in source
        assert "SymbolType" not in source
        assert source.count("entry_points(") == 1

    def test_get_entry_points(self):
        source = IMPORTS_EXPORTS_PY.read_text(encoding="utf-8")
        body = _between(source, "def get_entry_points(", None)
        assert "isExternalEntryPoint()" not in body
        assert "isExternalAddress()" not in body
        assert body.count("entry_points(") == 1
        # get_exports keeps its own (symbol-level) definition.
        exports = _between(source, "def get_exports(", "def get_entry_points(")
        assert "isExternalEntryPoint()" in exports

    def test_entrypoints_resource(self):
        source = RESOURCES_PY.read_text(encoding="utf-8")
        body = _between(source, "def _iter_entrypoints(", "def _iter_imports(")
        assert "isExternalEntryPoint()" not in body
        assert body.count("entry_points(") == 1

    def test_statistics_resource(self):
        source = RESOURCES_PY.read_text(encoding="utf-8")
        body = _between(source, "def db_statistics(", None)
        assert "isExternalEntryPoint()" not in body
        assert body.count("entry_points(") == 1

    def test_exports_resource_keeps_its_own_definition(self):
        source = RESOURCES_PY.read_text(encoding="utf-8")
        body = _between(source, "def _iter_exports(", "def register(")
        assert "isExternalEntryPoint()" in body

    def test_result_fields_point_at_get_entry_points(self):
        for model in (DatabaseInfoResult, AnalysisCompleteResult):
            desc = (model.model_fields["entry_point_count"].description or "").lower()
            assert "entry point addresses" in desc
            assert "get_entry_points" in desc

    def test_docs_say_one_item_per_address(self):
        rows = [
            line
            for line in DOCS_TOOLS_MD.read_text(encoding="utf-8").splitlines()
            if line.startswith("| `get_entry_points`")
        ]
        assert len(rows) == 1
        assert "one item per entry point address" in rows[0].lower()
        assert "primary symbol" in rows[0]
