# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Database information and lifecycle tools."""

from __future__ import annotations

import logging
import os
from typing import Any

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import ANNO_MUTATE, ANNO_READ_ONLY, format_address
from re_mcp_ghidra.session import session

log = logging.getLogger(__name__)


def loaded_memory_bounds(memory: Any, default_space: Any = None) -> tuple[Any, Any]:
    """Return ``(min, max)`` :class:`Address` over the *loaded* memory blocks only.

    ``Memory.getMinAddress()``/``getMaxAddress()`` span every address space in
    the program, including the non-loaded OTHER space and the overlays the ELF
    loader bases on it, such as ``_elfSectionHeaders``.  Because
    ``Address.getOffset()`` drops the space, an offset belonging to an unrelated
    space gets rendered as if it were a default-space address — an ELF program
    reports ``max_address 0x77f`` below its own ``min_address`` (#27).

    A block qualifies when both hold (Ghidra 12.1.2 paths below):

    * ``Address.isLoadedMemoryAddress()`` — rejects the non-loaded spaces: the
      OTHER space and the overlays the ELF loader bases on it
      (``_elfSectionHeaders``, ``.shstrtab``, ``.gnu_debuglink``).  It does
      *not* reject overlays as such — an overlay over loaded memory is itself a
      loaded memory space and is kept.  This is what makes the ELF inversion go
      away.
    * ``not MemoryBlock.isArtificial()`` — rejects blocks a loader or analyzer
      *fabricated*, which "do not exist in the same form within a
      running/loaded process state" (``MemoryBlock.java:210-218``; the flag bit
      is ``ARTIFICIAL = 0x10`` at ``MemoryBlock.java:51``).  This is what
      excludes the PE ``tdb`` Thread Environment Block
      at ``0xFF00000000``, created *after* import by the Windows analyzer
      (``ThreadEnvironmentBlock.java:75`` names it; ``:725``/``:810`` call
      ``setArtificial(true)``), and the ELF ``EXTERNAL`` import block
      (``MemoryBlockUtils.java:409``).

    Do **not** reach for ``MemoryBlock.isLoaded()`` here.  Its javadoc at
    ``MemoryBlock.java:370-374`` promises "a real loaded block (i.e. RAM) and
    not a special block containing file header data such as debug sections",
    but its only implementation is ``return
    startAddress.getAddressSpace().isLoadedMemorySpace();``
    (``MemoryBlockDB.java:433-435``) — literally the address test above.  It is
    ``True`` for all eight blocks of an analyzed ``curl.exe``, ``tdb``
    included, so filtering on it is a no-op.

    Membership is *not* narrowed further than that.  ``isInitialized()`` would
    drop ELF ``.bss``, which is real image memory and ends the image; PE
    ``Headers`` is genuine file content and legitimately sets ``min_address`` to
    the image base.

    When no block qualifies, a bounded fallback retries with the address test
    alone (a program made entirely of fabricated blocks should still report its
    extent instead of ``0x0``), and only then gives up.  That precedence —
    exclude, then fall back rather than report nothing — is what
    :class:`DatabaseInfoResult` and the ``docs/tools.md`` row promise.

    The returned pair always comes from a *single* address space, because the
    caller serialises ``getOffset()`` and a pair straddling two spaces
    re-creates the very inversion #27 is about.  The space is chosen
    deterministically: *default_space* when it holds a qualifying block,
    otherwise the space of the qualifying block that sorts lowest under
    ``Address.compareTo`` (space first, then offset) — never raw offsets, and
    never dependent on ``getBlocks()`` ordering.  A block contributes only when
    its start *and* its end lie in that space.  Testing the end is a defensive
    invariant with no known reachable trigger: a real ``MemoryBlock`` is one
    contiguous range inside a single address space, so it cannot straddle two.

    ``default_space`` is passed in rather than derived from a ``Program`` so the
    function stays callable with plain fake objects in the pure test suite.

    Returns ``(None, None)`` when no usable block exists.
    """
    all_blocks = list(memory.getBlocks())
    blocks = [
        b for b in all_blocks if b.getStart().isLoadedMemoryAddress() and not b.isArtificial()
    ]
    if not blocks:
        # Bounded fallback: keep reporting *something* for a program built
        # entirely out of fabricated blocks, rather than 0x0/0x0.
        blocks = [b for b in all_blocks if b.getStart().isLoadedMemoryAddress()]
    if not blocks:
        return (None, None)

    space = None
    if default_space is not None and any(
        b.getStart().getAddressSpace() == default_space for b in blocks
    ):
        space = default_space
    else:
        lowest_start = None
        for block in blocks:
            start = block.getStart()
            if lowest_start is None or start.compareTo(lowest_start) < 0:
                lowest_start = start
        space = lowest_start.getAddressSpace()

    lowest = highest = None
    for block in blocks:
        start, end = block.getStart(), block.getEnd()
        if start.getAddressSpace() != space or end.getAddressSpace() != space:
            continue
        if lowest is None or start.compareTo(lowest) < 0:
            lowest = start
        if highest is None or end.compareTo(highest) > 0:
            highest = end
    return (lowest, highest)


def count_functions(func_mgr: Any) -> tuple[int, int]:
    """Return ``(internal, external)`` function counts.

    ``FunctionManager.getFunctionCount()`` includes external (import thunk)
    functions, but ``getFunctions(True)`` — what ``list_functions`` iterates —
    does not.  Reporting the raw count made ``get_database_info.function_count``
    disagree with ``list_functions.total`` by exactly the number of externals
    (2006 vs 1775 on a PE, 543 vs 403 on an ELF) (#29).
    """
    external = sum(1 for _ in func_mgr.getExternalFunctions())
    internal = func_mgr.getFunctionCount() - external
    return (internal, external)


def database_info_paths(session_path: str | None, importer_path: str | None) -> tuple[str, str]:
    """Return ``(file_path, executable_path)`` for ``get_database_info``.

    ``Program.getExecutablePath()`` gives the path as the Ghidra importer
    recorded it, which on Windows is normalised to a leading-slash forward-slash
    form (``/C:/Users/.../curl.exe``).  ``open_database`` and ``list_databases``
    report the OS path the caller passed in, so the three tools disagreed on the
    same database (#31).  The session path therefore wins, with the importer
    path kept as a fallback and surfaced separately.

    Both arguments accept ``None`` because ``getExecutablePath()`` may return a
    Java null and the session may not have a path yet.
    """
    file_path = session_path or importer_path or ""
    return (file_path, importer_path or "")


class OpenDatabaseResult(BaseModel):
    status: str = Field(description="Operation status.")
    path: str = Field(description="Path to the opened file.")
    pid: int = Field(description="Worker process ID.")
    processor: str = Field(description="Processor/language ID.")
    bitness: int = Field(description="Address size in bits.")
    file_type: str = Field(description="File format.")
    function_count: int = Field(description="Number of functions.")
    external_function_count: int = Field(
        default=0,
        description=(
            "External (import thunk) functions, not included in function_count "
            "and not listed by list_functions."
        ),
    )
    segment_count: int = Field(description="Number of memory segments.")
    capabilities: dict[str, bool] = Field(description="Available capabilities.")
    warnings: list[str] = Field(default_factory=list, description="Any warnings.")
    analyzed: bool = Field(
        default=False,
        description=(
            "True when the database was already analyzed when opened; "
            "wait_for_analysis will not re-run analysis."
        ),
    )


class DatabaseInfoResult(BaseModel):
    file_path: str = Field(
        description="Path to the binary, as the OS spells it (same value as open_database.path)."
    )
    executable_path: str = Field(
        default="",
        description="Path as recorded by the Ghidra importer (normalised, may start with '/').",
    )
    file_type: str = Field(description="File format.")
    processor: str = Field(description="Processor/language.")
    compiler_spec: str = Field(description="Compiler specification.")
    bitness: int = Field(description="Address size in bits.")
    endian: str = Field(description="Byte order (big/little).")
    min_address: str = Field(
        description=(
            "Lowest address of loaded memory (hex). Both bounds come from one "
            "address space - the default address space unless it holds no "
            "qualifying block. Excluded are blocks Ghidra marks artificial "
            "because a loader or analyzer fabricated them rather than reading "
            "them from the image (the PE 'tdb' thread-environment block, the "
            "ELF 'EXTERNAL' import block), and blocks outside a loaded memory "
            "space (ELF section headers and other overlay/OTHER blocks, e.g. "
            "'_elfSectionHeaders'). PE headers are real image content and are "
            "kept. If that leaves nothing, the bounds fall back to whatever "
            "loaded blocks exist, artificial ones included, so the field still "
            "describes the program's extent."
        )
    )
    max_address: str = Field(
        description=(
            "Highest address of loaded memory (hex). Both bounds come from one "
            "address space - the default address space unless it holds no "
            "qualifying block. Excluded are blocks Ghidra marks artificial "
            "because a loader or analyzer fabricated them rather than reading "
            "them from the image (the PE 'tdb' thread-environment block, the "
            "ELF 'EXTERNAL' import block), and blocks outside a loaded memory "
            "space (ELF section headers and other overlay/OTHER blocks, e.g. "
            "'_elfSectionHeaders'). PE headers are real image content and are "
            "kept. If that leaves nothing, the bounds fall back to whatever "
            "loaded blocks exist, artificial ones included, so the field still "
            "describes the program's extent."
        )
    )
    image_base: str = Field(description="Image base address (hex).")
    function_count: int = Field(description="Number of functions.")
    external_function_count: int = Field(
        default=0,
        description=(
            "External (import thunk) functions, not included in function_count "
            "and not listed by list_functions."
        ),
    )
    segment_count: int = Field(description="Number of memory blocks.")
    entry_point_count: int = Field(description="Number of entry points.")
    capabilities: dict[str, bool] = Field(description="Available capabilities.")


class SaveDatabaseResult(BaseModel):
    """Result of saving a database."""

    status: str = Field(description="Status message.")
    path: str = Field(description="Path to the saved database file.")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"database"})
    def open_database(
        file_path: str,
        run_auto_analysis: bool = False,
        force_new: bool = False,
        language: str = "",
        compiler_spec: str = "",
    ) -> OpenDatabaseResult:
        """Open a binary for analysis. Called by the worker on supervisor's behalf."""
        result = session.open(
            file_path,
            run_auto_analysis=run_auto_analysis,
            force_new=force_new,
            language=language,
            compiler_spec=compiler_spec,
        )

        program = session.program
        lang = program.getLanguage()
        mem = program.getMemory()
        internal_funcs, external_funcs = count_functions(program.getFunctionManager())

        return OpenDatabaseResult(
            status="ok",
            path=result["path"],
            pid=os.getpid(),
            processor=str(lang.getLanguageID()),
            bitness=lang.getLanguageDescription().getSize(),
            file_type=program.getExecutableFormat() or "unknown",
            function_count=internal_funcs,
            external_function_count=external_funcs,
            segment_count=len(list(mem.getBlocks())),
            capabilities=session.capabilities,
            warnings=result.get("warnings", []),
            analyzed=result.get("analyzed", False),
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"database"})
    @session.require_open
    def close_database(save: bool = True) -> dict:
        """Close the current database."""
        return session.close(save=save)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"database"})
    @session.require_open
    def get_database_info() -> DatabaseInfoResult:
        """Get metadata about the currently open database."""
        program = session.program
        lang = program.getLanguage()
        mem = program.getMemory()
        func_mgr = program.getFunctionManager()
        sym_table = program.getSymbolTable()

        blocks = list(mem.getBlocks())
        # Real image blocks only, from one address space: OTHER-space blocks
        # and analyzer-fabricated ones (PE 'tdb', ELF 'EXTERNAL') would
        # otherwise contribute a bare offset that renders as an unrelated
        # default-space address (#27).
        default_space = program.getAddressFactory().getDefaultAddressSpace()
        min_addr, max_addr = loaded_memory_bounds(mem, default_space)
        internal_funcs, external_funcs = count_functions(func_mgr)

        entry_count = sum(1 for s in sym_table.getAllSymbols(True) if s.isExternalEntryPoint())

        # The session path is the OS path the caller opened; the importer's is
        # normalised ("/C:/..." on Windows) and is reported separately (#31).
        file_path, executable_path = database_info_paths(
            session.current_path, program.getExecutablePath()
        )

        return DatabaseInfoResult(
            file_path=file_path,
            executable_path=executable_path,
            file_type=program.getExecutableFormat() or "unknown",
            processor=str(lang.getLanguageID()),
            compiler_spec=str(program.getCompilerSpec().getCompilerSpecID()),
            bitness=lang.getLanguageDescription().getSize(),
            endian="big" if lang.isBigEndian() else "little",
            min_address=format_address(min_addr.getOffset()) if min_addr else "0x0",
            max_address=format_address(max_addr.getOffset()) if max_addr else "0x0",
            image_base=format_address(program.getImageBase().getOffset()),
            function_count=internal_funcs,
            external_function_count=external_funcs,
            segment_count=len(blocks),
            entry_point_count=entry_count,
            capabilities=session.capabilities,
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"database"})
    @session.require_open
    def save_database(outfile: str = "", flags: int = -1) -> SaveDatabaseResult:
        """Save the current database to disk.

        Args:
            outfile: Not supported for Ghidra (raises an error if provided).
            flags: Ignored (IDA-specific).
        """
        if outfile:
            raise GhidraError(
                "Ghidra does not support saving to an alternate path.",
                error_type="UnsupportedOperation",
            )
        session.save()
        log.debug("save_database: after save %s", session._tx_state())
        return SaveDatabaseResult(status="saved", path=session.current_path)
