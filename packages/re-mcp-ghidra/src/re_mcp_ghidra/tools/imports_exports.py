# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Import, export, and entry point enumeration tools."""

from __future__ import annotations

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.helpers import (
    ANNO_READ_ONLY,
    Limit,
    Offset,
    describe_external,
    format_address,
    paginate_iter,
)
from re_mcp_ghidra.session import session
from re_mcp_ghidra.tools.database import entry_points


class ImportItem(BaseModel):
    """An imported symbol."""

    module: str = Field(description="External library/module name.")
    address: str | None = Field(
        description=(
            "Memory address of the import's thunk (PE stub / ELF PLT entry); null "
            "when the import is only reached through its IAT pointer. Use "
            "get_xrefs_to on it to find direct callers."
        )
    )
    name: str = Field(description="Import name.")
    external_address: str = Field(
        description=(
            "EXTERNAL:<library>::<name>; the value get_xrefs_from and "
            "get_call_graph show for this import."
        )
    )


class ExportItem(BaseModel):
    """An exported symbol."""

    address: str = Field(description="Export address (hex).")
    name: str = Field(description="Export name.")


class EntryPointItem(BaseModel):
    """An entry point."""

    address: str = Field(description="Entry point address (hex).")
    name: str = Field(description="Primary symbol at the address; empty when there is none.")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"metadata"})
    @session.require_open
    def get_imports(
        module_filter: str = "",
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """List all imported functions/symbols.

        Use module_filter to narrow results to a specific library (e.g.
        "kernel32", "libc"). ``address`` is the import's thunk (PE stub or
        ELF PLT entry) — use get_xrefs_to on it to find all code that calls
        it; it is null for an import only reached through its IAT pointer.
        ``external_address`` is the EXTERNAL:<library>::<name> form that
        get_xrefs_from and get_call_graph show for the same import.

        Args:
            module_filter: Optional substring to filter module/library names (case-insensitive).
            offset: Pagination offset.
            limit: Maximum number of import entries.
        """
        program = session.program
        filter_lower = module_filter.lower()

        def _gen():
            ext_mgr = program.getExternalManager()
            for lib_name in ext_mgr.getExternalLibraryNames():
                if filter_lower and filter_lower not in lib_name.lower():
                    continue
                for ext_loc in ext_mgr.getExternalLocations(lib_name):
                    sym = ext_loc.getSymbol()
                    if sym is None:
                        continue
                    ext = describe_external(program, ext_loc.getExternalSpaceAddress())
                    yield ImportItem(
                        module=lib_name,
                        address=ext["thunk_address"],
                        name=sym.getName(),
                        external_address=ext["address"],
                    ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"metadata"})
    @session.require_open
    def get_exports(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """List all exported symbols.

        Good starting point for analyzing shared libraries or DLLs --
        exports are the public API. Use get_xrefs_to on an export address
        to find internal callers.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        program = session.program
        sym_table = program.getSymbolTable()

        def _gen():
            sym_iter = sym_table.getAllSymbols(True)
            for sym in sym_iter:
                if sym.isExternalEntryPoint():
                    addr = sym.getAddress()
                    if addr.isExternalAddress():
                        continue
                    yield ExportItem(
                        address=format_address(addr.getOffset()),
                        name=sym.getName(),
                    ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"metadata"})
    @session.require_open
    def get_entry_points(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """List binary entry points (main/start/exports).

        Entry points are addresses where execution may begin; one item per
        entry point address, named after its primary symbol (the same set
        get_database_info.entry_point_count counts).  For shared libraries,
        get_exports is more complete (includes all exported symbols).

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        program = session.program
        sym_table = program.getSymbolTable()

        def _gen():
            for addr, name in entry_points(sym_table):
                yield EntryPointItem(
                    address=format_address(addr.getOffset()),
                    name=name,
                ).model_dump()

        return paginate_iter(_gen(), offset, limit)
