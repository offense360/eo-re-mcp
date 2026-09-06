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
