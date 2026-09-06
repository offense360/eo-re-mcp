# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Ghidra-specific utilities for address resolution, dispatching, and tool helpers.

Imports and re-exports shared helpers from :mod:`re_mcp.helpers` so that
tool modules can import everything from a single place.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any

from re_mcp.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_MUTATE_NON_IDEMPOTENT,
    ANNO_READ_ONLY,
    Address,
    FilterPattern,
    HexBytes,
    Limit,
    Offset,
    async_paginate_iter,
    compile_filter,
    dispatch_to_main,
    format_address,
    paginate,
    paginate_iter,
    parse_address,
    set_main_executor,
)

from re_mcp_ghidra.exceptions import GhidraError

log = logging.getLogger(__name__)

__all__ = [
    "ANNO_DESTRUCTIVE",
    "ANNO_MUTATE",
    "ANNO_MUTATE_NON_IDEMPOTENT",
    "ANNO_READ_ONLY",
    "Address",
    "FilterPattern",
    "GhidraError",
    "HexBytes",
    "Limit",
    "Offset",
    "async_paginate_iter",
    "call_ghidra",
    "check_range_in_memory",
    "compile_filter",
    "describe_external",
    "format_address",
    "format_permissions",
    "is_external_address",
    "paginate",
    "paginate_iter",
    "parse_address",
    "read_memory",
    "resolve_address",
    "resolve_address_value",
    "resolve_function",
    "set_main_executor",
    "to_ghidra_address",
    "transaction",
    "write_memory",
]

# Backend dispatch alias
call_ghidra = dispatch_to_main


# ---------------------------------------------------------------------------
# EXTERNAL space (imported symbols)
# ---------------------------------------------------------------------------


def is_external_address(addr: Any) -> bool:
    """True when *addr* lies in Ghidra's artificial EXTERNAL address space."""
    return addr is not None and addr.isExternalAddress()


def describe_external(program: Any, addr: Any) -> dict[str, Any]:
    """Render an EXTERNAL-space address (an imported symbol) for tool output (#43).

    Returns ``address`` = ``"EXTERNAL:<library>::<name>"`` (Ghidra's own
    qualified name, ``Symbol.getName(True)``; ``"EXTERNAL:0x<offset>"`` when no
    symbol is there), ``symbol``, ``library`` and ``thunk_address`` — the
    address of the thunk that lives in real (non-artificial) memory: the PE
    stub or the ELF ``.plt``/``.plt.sec`` entry, which is what callers
    reference.  Ghidra's analyzer-made ELF ``EXTERNAL`` block holds a
    body-less first-hop stub for every import (``free`` at ``0x149268``, two
    references) and is skipped; when no hop is in real memory the first hop is
    kept.  ``None`` when the import is only reached through its IAT pointer.

    The offset of an EXTERNAL address is a slot index (``free`` is
    ``EXTERNAL:0xb0``), so it must never be formatted as a memory address.
    ``ExternalLocation.getAddress()`` is not used either: on a PE it holds a
    meaningless value (negative for ordinal imports).
    """
    sym = program.getSymbolTable().getPrimarySymbol(addr)
    loc = program.getExternalManager().getExternalLocation(sym) if sym else None
    func = loc.getFunction() if loc and loc.isFunction() else None
    # Java null (no thunk) or an empty array: ``if thunks`` handles both.
    # Recursive: innermost hop first, so the ELF EXTERNAL-block stub precedes
    # the .plt.sec entry; prefer the first hop whose block is not artificial.
    thunks = func.getFunctionThunkAddresses(True) if func else None
    thunk = None
    if thunks:
        memory = program.getMemory()
        thunk = next(
            (t for t in thunks if (b := memory.getBlock(t)) is not None and not b.isArtificial()),
            thunks[0],
        )
    return {
        "address": f"EXTERNAL:{sym.getName(True)}" if sym else f"EXTERNAL:{addr.getOffset():#x}",
        "symbol": sym.getName() if sym else "",
        "library": loc.getLibraryName() if loc else "",
        "thunk_address": format_address(thunk.getOffset()) if thunk is not None else None,
    }


# ---------------------------------------------------------------------------
# Transactions
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def transaction(program, label: str):
    """Run a mutation inside a Ghidra transaction.

    Ends the transaction with ``commit=False`` on error, so a failed tool
    leaves nothing behind.  This is only safe because the session no longer
    keeps a standing "Batch Processing" transaction open (#18): a tool
    transaction is now the outermost one, and aborting it rolls back that
    tool's own changes and nothing else.  Under ``GhidraProject`` an aborted
    nested entry marked the whole batch ABORTED and Ghidra rolled back every
    change since the last save, which is why this used to always commit (#11).
    """
    tx_id = program.startTransaction(label)
    success = True
    try:
        yield
    except Exception as exc:
        success = False
        log.warning(
            "Transaction %r raised %s: %s; the transaction was rolled back; nothing "
            "from this call was kept (#18).",
            label,
            type(exc).__name__,
            exc,
        )
        raise
    finally:
        program.endTransaction(tx_id, success)


# ---------------------------------------------------------------------------
# Ghidra-specific address resolution (extends parse_address with symbol lookup)
# ---------------------------------------------------------------------------


def resolve_address_value(addr: str | int) -> int:
    """Parse an address string into an integer, checking Ghidra symbols if needed.

    This is called from within a Ghidra context where the program is available.
    Raises :class:`GhidraError` on failure.
    """
    from re_mcp_ghidra.session import session  # noqa: PLC0415

    if isinstance(addr, int):
        return addr

    addr_str = str(addr).strip()
    if not addr_str:
        raise GhidraError("Empty address", error_type="InvalidAddress")

    # Try numeric parsing first
    try:
        return parse_address(addr_str)
    except ValueError:
        pass

    # Try as symbol name via Ghidra
    program = session.program
    if program is None:
        raise GhidraError("No database is open", error_type="NoDatabase")

    symbol_table = program.getSymbolTable()
    symbols = symbol_table.getGlobalSymbols(addr_str)
    if symbols:
        return symbols[0].getAddress().getOffset()

    # Try namespace-qualified symbols via targeted lookup
    sym_iter = symbol_table.getSymbols(addr_str)
    if sym_iter.hasNext():
        return sym_iter.next().getAddress().getOffset()

    raise GhidraError(f"Cannot resolve address: {addr_str!r}", error_type="InvalidAddress")


def _format_offset(offset: int) -> str:
    """Format an offset for an error message, keeping negatives readable.

    ``format_address`` renders a negative integer as ``0x-1``; a leading sign
    reads better when the value is being reported back to a client.
    """
    if offset < 0:
        return f"-{format_address(-offset)}"
    return format_address(offset)


def to_ghidra_address(offset: int):
    """Convert an integer offset to a Ghidra Address object.

    ``parse_address`` accepts Python integers of any size, so an out-of-range
    value used to reach JPype and escape as a bare
    ``OverflowError: int too big to convert`` — no ``error_type``, no offending
    address, and no JSON error body for the client (#28).  Both the range check
    and the conversion now report ``error_type="InvalidAddress"``.
    """
    from re_mcp_ghidra.session import session  # noqa: PLC0415

    program = session.program
    if program is None:
        raise GhidraError("No database is open", error_type="NoDatabase")

    space = program.getAddressFactory().getDefaultAddressSpace()
    max_off = space.getMaxAddress().getOffset()
    if max_off < 0:
        # JPype hands back a Java signed long, so a 64-bit space reports -1.
        max_off &= 0xFFFFFFFFFFFFFFFF
    if offset < 0 or offset > max_off:
        raise GhidraError(
            f"Address {_format_offset(offset)} is outside the program's address space "
            f"(0x0-{format_address(max_off)})",
            error_type="InvalidAddress",
        )

    try:
        return space.getAddress(offset)
    except GhidraError:
        raise
    except Exception as exc:
        raise GhidraError(
            f"Invalid address {_format_offset(offset)}: {exc}",
            error_type="InvalidAddress",
        ) from exc


def resolve_address(addr: str | int):
    """Parse and validate an address, returning a Ghidra Address object.

    Raises :class:`GhidraError` with ``error_type="InvalidAddress"`` on failure.
    """
    offset = resolve_address_value(addr)
    return to_ghidra_address(offset)


def resolve_function(addr: str | int):
    """Resolve an address to its containing function.

    Returns a Ghidra Function object. Raises :class:`GhidraError` if not found.
    """
    from re_mcp_ghidra.session import session  # noqa: PLC0415

    program = session.program
    if program is None:
        raise GhidraError("No database is open", error_type="NoDatabase")

    ghidra_addr = resolve_address(addr)
    func = program.getFunctionManager().getFunctionContaining(ghidra_addr)
    if func is None:
        raise GhidraError(
            f"No function at {format_address(ghidra_addr.getOffset())}",
            error_type="NotFound",
        )
    return func


# ---------------------------------------------------------------------------
# Ghidra-specific permission formatting
# ---------------------------------------------------------------------------


def format_permissions(read: bool, write: bool, execute: bool) -> str:
    """Format permission flags as a string like ``"RWX"``."""
    s = "R" if read else "-"
    s += "W" if write else "-"
    s += "X" if execute else "-"
    return s


# ---------------------------------------------------------------------------
# Memory reading (jpype-safe)
# ---------------------------------------------------------------------------


def read_memory(memory, addr, size: int) -> bytes:
    """Read bytes from Ghidra memory using a proper Java byte array.

    Python bytearray is not updated in-place by jpype when passed to Java
    methods, so we must use jpype.JArray(jpype.JByte) instead.
    """
    if size <= 0:
        return b""
    import jpype  # noqa: PLC0415

    buf = jpype.JArray(jpype.JByte)(size)
    memory.getBytes(addr, buf)
    return bytes(b & 0xFF for b in buf)


def check_range_in_memory(program, addr, size: int, *, initialized: bool = False) -> None:
    """Raise :class:`GhidraError` unless ``[addr, addr + size)`` is backed by memory blocks.

    Mirrors the pre-flight walk ``MemoryMapDB.setBytes`` performs, so tools can
    reject a bad range *before* they start mutating (clearing code units,
    creating data, ...). With ``initialized=True`` every block in the range
    must also be initialized, which is what a byte write requires.
    """
    if size <= 0:
        raise GhidraError("size must be >= 1", error_type="InvalidArgument")
    memory = program.getMemory()
    try:
        end_addr = addr.add(size - 1)
    except Exception as e:
        raise GhidraError(
            f"Invalid range {format_address(addr.getOffset())} (+{size})",
            error_type="InvalidArgument",
        ) from e
    cur = addr
    while True:
        block = memory.getBlock(cur)
        if block is None:
            raise GhidraError(
                f"Address {format_address(cur.getOffset())} is not in memory "
                f"(range {format_address(addr.getOffset())} +{size})",
                error_type="NotFound",
            )
        if initialized and not block.isInitialized():
            raise GhidraError(
                f"Memory block {block.getName()} at {format_address(cur.getOffset())} "
                "is uninitialized",
                error_type="InvalidArgument",
            )
        if block.contains(end_addr):
            return
        cur = block.getEnd().add(1)


def write_memory(program, addr, data: bytes, *, label: str = "Write bytes") -> None:
    """Write bytes to Ghidra memory within a transaction.

    Clears existing code units in the target range before writing to avoid
    conflicts with existing instructions/data definitions. The range is
    validated first so a bad address fails before anything is cleared (#11).

    Raises :class:`GhidraError` on failure.
    """
    if not data:
        raise GhidraError("Cannot write empty data", error_type="InvalidArgument")
    check_range_in_memory(program, addr, len(data), initialized=True)
    try:
        with transaction(program, label):
            end_addr = addr.add(len(data) - 1)
            program.getListing().clearCodeUnits(addr, end_addr, False)
            program.getMemory().setBytes(addr, data)
    except GhidraError:
        raise
    except Exception as e:
        raise GhidraError(f"Failed to write bytes: {e}", error_type="PatchFailed") from e
