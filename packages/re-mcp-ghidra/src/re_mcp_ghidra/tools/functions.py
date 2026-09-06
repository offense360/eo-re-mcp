# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Function analysis tools — list, decompile, disassemble, rename."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    FilterPattern,
    Limit,
    Offset,
    PseudocodeLine,
    PseudocodeLines,
    compile_filter,
    disassembly_note,
    format_address,
    normalize_pseudocode,
    page_lines,
    paginate,
    paginate_iter,
    resolve_function,
    transaction,
)
from re_mcp_ghidra.models import FunctionSummary, RenameResult
from re_mcp_ghidra.session import session


class FunctionDetail(BaseModel):
    name: str
    start: str
    end: str
    size: int
    calling_convention: str = ""
    signature: str = ""
    is_thunk: bool = False
    is_external: bool = False
    comment: str = ""
    entry_point: str = ""


class DecompilationResult(BaseModel):
    function_name: str
    address: str
    decompiled_code: str = Field(
        description=(
            "This page of the decompiled C pseudocode (lines start_line .. start_line+n-1); "
            "LF line endings, no leading/trailing blank lines (same shape as IDA's pseudocode)."
        )
    )
    line_count: int = Field(description="Total pseudocode lines in the whole function.")
    start_line: int = Field(description="0-based line this page starts at.")
    max_lines: int = Field(description="Requested page size.")
    has_more: bool = Field(description="True when lines after this page remain.")
    next_line: int | None = Field(
        default=None, description="start_line for the next page, or null on the last page."
    )
    note: str | None = Field(
        default=None, description="How to fetch the rest; only set when has_more is true."
    )


class Instruction(BaseModel):
    address: str
    bytes: str
    mnemonic: str
    operands: str


class DisassemblyResult(BaseModel):
    function_name: str
    start: str
    end: str
    instruction_count: int = Field(
        description="Total instructions in the function, not just this page."
    )
    instructions: list[Instruction] = Field(description="This page of instructions.")
    offset: int = Field(description="Index of the first instruction on this page.")
    limit: int = Field(description="Requested page size.")
    has_more: bool = Field(description="True when instructions after this page remain.")
    note: str | None = Field(
        default=None, description="How to fetch the rest; only set when has_more is true."
    )


# Decompiled, normalized pseudocode per function (#41).  Keyed by
# (unique program id, entry offset); the value carries the program's
# modification number, which Ghidra bumps on every change, undo and redo
# (DomainObject.getModificationNumber), so a stale entry is simply replaced.
# Bounded so memory stays small; entries of closed programs age out.
_DECOMPILE_CACHE: OrderedDict[tuple[int, int], tuple[int, str]] = OrderedDict()
_DECOMPILE_CACHE_SIZE = 8


def cached_decompile(program, func, decompile: Callable[[], str]) -> str:
    """Return the normalized pseudocode of ``func``, decompiling only when needed.

    ``decompile`` runs when there is no entry for the function or the
    program's modification number changed since the entry was stored.
    Both ids come back from pyghidra as ``JLong``; ``int()`` keeps the
    keys hashable and comparable across calls.
    """
    key = (int(program.getUniqueProgramID()), int(func.getEntryPoint().getOffset()))
    mod = int(program.getModificationNumber())
    entry = _DECOMPILE_CACHE.get(key)
    if entry is not None and entry[0] == mod:
        _DECOMPILE_CACHE.move_to_end(key)
        return entry[1]
    code = decompile()
    _DECOMPILE_CACHE[key] = (mod, code)
    _DECOMPILE_CACHE.move_to_end(key)
    while len(_DECOMPILE_CACHE) > _DECOMPILE_CACHE_SIZE:
        _DECOMPILE_CACHE.popitem(last=False)
    return code


class DeleteFunctionResult(BaseModel):
    address: str
    name: str
    status: str


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"functions"})
    @session.require_open
    def list_functions(
        offset: Offset = 0,
        limit: Limit = 100,
        filter_pattern: FilterPattern = "",
    ) -> dict:
        """List all functions in the database, paginated with optional regex filter.

        External functions are not listed; see get_database_info.external_function_count.
        """
        program = session.program
        func_mgr = program.getFunctionManager()
        filt = compile_filter(filter_pattern)

        def _gen():
            func_iter = func_mgr.getFunctions(True)
            while func_iter.hasNext():
                func = func_iter.next()
                name = func.getName()
                if filt and not filt.search(name):
                    continue
                body = func.getBody()
                start = func.getEntryPoint().getOffset()
                end = body.getMaxAddress().getOffset() + 1 if body.getNumAddresses() > 0 else start
                yield FunctionSummary(
                    name=name,
                    start=format_address(start),
                    end=format_address(end),
                    size=int(body.getNumAddresses()),
                ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"functions"})
    @session.require_open
    def get_function(address: Address) -> FunctionDetail:
        """Get detailed information about a function."""
        func = resolve_function(address)
        body = func.getBody()
        entry = func.getEntryPoint()
        start = entry.getOffset()
        end = body.getMaxAddress().getOffset() + 1 if body.getNumAddresses() > 0 else start

        return FunctionDetail(
            name=func.getName(),
            start=format_address(start),
            end=format_address(end),
            size=int(body.getNumAddresses()),
            calling_convention=func.getCallingConventionName() or "",
            signature=func.getPrototypeString(False, False) or "",
            is_thunk=func.isThunk(),
            is_external=func.isExternal(),
            comment=func.getComment() or "",
            entry_point=format_address(start),
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"functions", "decompiler"})
    @session.require_open
    def decompile_function(
        address: Address,
        start_line: PseudocodeLine = 0,
        max_lines: PseudocodeLines = 2000,
    ) -> DecompilationResult:
        """Decompile a function to C pseudocode using Ghidra's decompiler.

        Returns up to `max_lines` lines (default 2000) from `start_line`;
        `line_count` is the whole function. Pass a larger `max_lines` to get
        everything at once. Line numbers are 0-based over the whole function.
        The decompiled text is cached per function until the database changes.
        """
        from ghidra.app.decompiler import DecompInterface  # noqa: PLC0415
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        func = resolve_function(address)
        program = session.program

        def _decompile() -> str:
            decomp = DecompInterface()
            decomp.openProgram(program)
            try:
                results = decomp.decompileFunction(func, 60, TaskMonitor.DUMMY)
                if not results.decompileCompleted():
                    error_msg = results.getErrorMessage() or "Decompilation failed"
                    raise GhidraError(error_msg, error_type="DecompilationFailed")

                decomp_func = results.getDecompiledFunction()
                if decomp_func is None:
                    raise GhidraError(
                        "Decompilation returned no result", error_type="DecompilationFailed"
                    )
                return normalize_pseudocode(decomp_func.getC())
            finally:
                decomp.dispose()

        code = cached_decompile(program, func, _decompile)
        page = page_lines(code.split("\n") if code else [], start_line, max_lines)

        return DecompilationResult(
            function_name=func.getName(),
            address=format_address(func.getEntryPoint().getOffset()),
            decompiled_code=page["text"],
            line_count=page["line_count"],
            start_line=page["start_line"],
            max_lines=page["max_lines"],
            has_more=page["has_more"],
            next_line=page["next_line"],
            note=page["note"],
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"functions"})
    @session.require_open
    def disassemble_function(
        address: Address, offset: Offset = 0, limit: Limit = 500
    ) -> DisassemblyResult:
        """Disassemble a function into individual instructions.

        Returns up to `limit` instructions (default 500) starting at `offset`;
        `instruction_count` is the whole function. Pass a larger `limit` to get
        everything at once.
        """
        func = resolve_function(address)
        program = session.program
        listing = program.getListing()
        body = func.getBody()

        instructions = []
        insn_iter = listing.getInstructions(body, True)
        while insn_iter.hasNext():
            insn = insn_iter.next()
            addr = insn.getAddress()
            raw_bytes = []
            for i in range(insn.getLength()):
                b = insn.getByte(i)
                raw_bytes.append(f"{b & 0xFF:02X}")

            operands = []
            for i in range(insn.getNumOperands()):
                op_str = insn.getDefaultOperandRepresentation(i)
                if op_str:
                    operands.append(op_str)

            instructions.append(
                Instruction(
                    address=format_address(addr.getOffset()),
                    bytes=" ".join(raw_bytes),
                    mnemonic=insn.getMnemonicString(),
                    operands=", ".join(operands),
                )
            )

        entry = func.getEntryPoint().getOffset()
        end_addr = body.getMaxAddress().getOffset() + 1 if body.getNumAddresses() > 0 else entry
        page = paginate(instructions, offset, limit)

        return DisassemblyResult(
            function_name=func.getName(),
            start=format_address(entry),
            end=format_address(end_addr),
            instruction_count=page["total"],
            instructions=page["items"],
            offset=page["offset"],
            limit=page["limit"],
            has_more=page["has_more"],
            note=disassembly_note(page["offset"], len(page["items"]), page["total"]),
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"functions"})
    @session.require_open
    def rename_function(address: Address, new_name: str) -> RenameResult:
        """Rename a function."""
        from ghidra.program.model.symbol import SourceType  # noqa: PLC0415

        func = resolve_function(address)
        old_name = func.getName()

        try:
            with transaction(session.program, "Rename function"):
                func.setName(new_name, SourceType.USER_DEFINED)
        except Exception as e:
            raise GhidraError(f"Failed to rename function: {e}", error_type="RenameFailed") from e

        return RenameResult(
            address=format_address(func.getEntryPoint().getOffset()),
            old_name=old_name,
            new_name=new_name,
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"functions"})
    @session.require_open
    def delete_function(address: Address) -> DeleteFunctionResult:
        """Delete a function definition (does not delete the bytes)."""
        func = resolve_function(address)
        name = func.getName()
        entry = func.getEntryPoint()

        try:
            with transaction(session.program, "Delete function"):
                success = session.program.getFunctionManager().removeFunction(entry)
            if not success:
                raise GhidraError("Failed to delete function", error_type="DeleteFailed")
        except GhidraError:
            raise
        except Exception as e:
            raise GhidraError(f"Failed to delete function: {e}", error_type="DeleteFailed") from e

        return DeleteFunctionResult(
            address=format_address(entry.getOffset()),
            name=name,
            status="deleted",
        )
