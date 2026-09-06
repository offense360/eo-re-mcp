# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Analysis control tools — reanalyze, wait for analysis, problem listing."""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    Limit,
    Offset,
    format_address,
    paginate_iter,
    resolve_address,
    transaction,
)
from re_mcp_ghidra.session import session
from re_mcp_ghidra.tools.database import count_functions, entry_points, loaded_memory_bounds


class ReanalyzeRangeResult(BaseModel):
    """Result of reanalyzing a range."""

    start: str = Field(description="Range start address (hex).")
    end: str = Field(description="Range end address (hex).")
    status: str = Field(description="Status message.")


class AnalysisCompleteResult(BaseModel):
    """Result of waiting for analysis to complete, with a database summary."""

    status: str = Field(description="Status: 'analysis_complete'.")
    function_count: int = Field(
        description=(
            "Number of functions after analysis, matching list_functions.total "
            "(external functions excluded, see get_database_info)."
        )
    )
    segment_count: int = Field(description="Number of memory blocks.")
    entry_point_count: int = Field(
        description="Number of entry point addresses (same set as get_entry_points)."
    )
    min_address: str = Field(
        description=(
            "Lowest address of loaded, non-artificial memory in one address space "
            "(hex); same definition as get_database_info.min_address."
        )
    )
    max_address: str = Field(
        description=(
            "Highest address of loaded, non-artificial memory in one address space "
            "(hex); same definition as get_database_info.max_address."
        )
    )


class AnalysisProblem(BaseModel):
    """An analysis problem (bookmark of type ERROR or WARNING)."""

    address: str = Field(description="Problem address (hex).")
    type: str = Field(description="Bookmark type (ERROR or WARNING).")
    category: str = Field(description="Bookmark category.")
    comment: str = Field(description="Bookmark comment.")


def analysis_bounds(program: Any) -> tuple[str, str]:
    """Formatted ``(min_address, max_address)`` for :class:`AnalysisCompleteResult`.

    Delegates to :func:`loaded_memory_bounds` so ``analyze_database`` (and the
    first ``wait_for_analysis``, which proxies it) reports exactly what
    ``get_database_info`` reports.  ``Program.getMinAddress``/``getMaxAddress``
    span every address space, so they returned the PE ``tdb`` end
    (``0xFF0000184F``) and the ELF section-header overlay end (``0x77F``)
    instead of the image extent (#44, #27).
    """
    lo, hi = loaded_memory_bounds(
        program.getMemory(), program.getAddressFactory().getDefaultAddressSpace()
    )
    return (
        format_address(lo.getOffset()) if lo else "0x0",
        format_address(hi.getOffset()) if hi else "0x0",
    )


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_MUTATE, tags={"analysis"})
    @session.require_open
    def reanalyze_range(
        start_address: Address,
        end_address: Address,
    ) -> ReanalyzeRangeResult:
        """Reanalyze an address range by running Ghidra auto-analysis on it.

        Call after patching bytes, changing types, or creating new code
        to force Ghidra to re-analyze the affected range.

        Args:
            start_address: Start of the range.
            end_address: End of the range (exclusive).
        """
        from ghidra.app.cmd.disassemble import DisassembleCommand  # noqa: PLC0415
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        program = session.program
        start = resolve_address(start_address)
        end = resolve_address(end_address)

        # Clear and re-disassemble the range, then run full analysis
        from ghidra.program.model.address import AddressSet  # noqa: PLC0415

        addr_set = AddressSet(start, end)

        try:
            with transaction(program, "Reanalyze range"):
                cmd = DisassembleCommand(addr_set, addr_set)
                cmd.applyTo(program, TaskMonitor.DUMMY)
        except Exception as e:
            raise GhidraError(f"Failed to reanalyze range: {e}", error_type="AnalysisFailed") from e

        # The session runs the pass inside its own "Analyze" transaction (#18).
        # The analyzed flag is left alone: this is a partial pass (#8).
        session.analyze(mark_analyzed=False)

        return ReanalyzeRangeResult(
            start=format_address(start.getOffset()),
            end=format_address(end.getOffset()),
            status="analysis_complete",
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"analysis"})
    @session.require_open
    def analyze_database() -> AnalysisCompleteResult:
        """Run Ghidra's auto-analysis to completion on the open program.

        Use this to fully analyze a database that was opened without analysis
        (``open_database`` defaults to ``run_auto_analysis=False``), or after
        making changes (patches, type applications) to ensure the program is
        fully analyzed before querying.  Returns a summary of database
        statistics after analysis finishes.
        """
        program = session.program

        # Runs the pass in one transaction and persists the analyzed flag so a
        # reopened project is not re-analyzed (#8, #18).
        session.analyze()

        func_mgr = program.getFunctionManager()
        memory = program.getMemory()
        sym_table = program.getSymbolTable()

        func_count, _external_count = count_functions(func_mgr)
        block_count = memory.getBlocks().__len__()

        entry_count = len(entry_points(sym_table))

        min_address, max_address = analysis_bounds(program)

        return AnalysisCompleteResult(
            status="analysis_complete",
            function_count=func_count,
            segment_count=block_count,
            entry_point_count=entry_count,
            min_address=min_address,
            max_address=max_address,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"analysis"})
    @session.require_open
    def get_analysis_problems(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """List analysis problems found by Ghidra (ERROR and WARNING bookmarks).

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        program = session.program
        bookmark_mgr = program.getBookmarkManager()

        def _gen():
            for bm_type in ("Error", "Warning"):
                bm_iter = bookmark_mgr.getBookmarksIterator(bm_type)
                while bm_iter.hasNext():
                    bm = bm_iter.next()
                    yield AnalysisProblem(
                        address=format_address(bm.getAddress().getOffset()),
                        type=bm.getTypeString(),
                        category=bm.getCategory() or "",
                        comment=bm.getComment() or "",
                    ).model_dump()

        return paginate_iter(_gen(), offset, limit)
