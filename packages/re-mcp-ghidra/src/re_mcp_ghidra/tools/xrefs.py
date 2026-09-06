# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Cross-reference analysis tools."""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.helpers import (
    ANNO_READ_ONLY,
    Address,
    Limit,
    Offset,
    describe_external,
    format_address,
    is_external_address,
    paginate_iter,
    resolve_address,
)
from re_mcp_ghidra.session import session


class XrefTo(BaseModel):
    from_address: str = Field(description="Source address (hex).")
    from_function: str = Field(description="Containing function name, if any.")
    ref_type: str = Field(description="Reference type.")
    is_call: bool = Field(description="True if this is a call reference.")


class XrefFrom(BaseModel):
    to_address: str = Field(
        description=("Target address (hex), or EXTERNAL:<library>::<name> for an imported symbol.")
    )
    to_function: str = Field(description="Target function name, if any.")
    ref_type: str = Field(description="Reference type.")
    is_call: bool = Field(description="True if this is a call reference.")
    library: str | None = Field(
        default=None,
        description=(
            "Library of the imported symbol when to_address is in Ghidra's "
            "EXTERNAL space, else null."
        ),
    )


class XrefsFromResult(BaseModel):
    """A page of references FROM an address."""

    items: list[XrefFrom] = Field(description="References on this page.")
    total: int = Field(description="Total memory references from the address.")
    offset: int = Field(description="Starting offset.")
    limit: int = Field(description="Maximum references per page.")
    has_more: bool = Field(description="Whether more references exist.")
    skipped_non_memory: int = Field(
        default=0,
        description=(
            "References omitted from items because their target is not a memory "
            "address: stack, register and constant targets only; references to "
            "imported symbols are kept as items with an EXTERNAL:... address. "
            "Counted across all references from the address, not just this page."
        ),
    )


class CallGraphEntry(BaseModel):
    name: str
    address: str
    callers: list[dict] = Field(default_factory=list)
    callees: list[dict] = Field(
        default_factory=list,
        description=(
            "Called functions; external callees (imports) appear once, by name, "
            "with address EXTERNAL:<library>::<name>, symbol, library and "
            "thunk_address (memory address of the import's thunk, or null), and "
            "are never expanded further."
        ),
    )


def is_memory_reference(ref) -> bool:
    """True when *ref* points at an address that can be rendered as a hex address.

    A ``Stack[0x8]`` or register target has an offset like any other address, so
    formatting it produces a plausible-looking but meaningless memory address
    (#30).  A reference to an imported symbol is dropped for the same reason:
    it targets Ghidra's artificial EXTERNAL space, where the offset is a slot
    index rather than an address any other tool can resolve.  Both the address
    space and the reference's own flags are checked:
    the flags are what Ghidra sets when it builds the reference, and the space
    is what decides whether the offset means anything to the other tools.
    """
    to = ref.getToAddress()
    return (
        to is not None
        and to.isMemoryAddress()
        and not ref.isStackReference()
        and not ref.isRegisterReference()
    )


def is_renderable_reference(ref) -> bool:
    """True when ``get_xrefs_from`` can show *ref* as an item.

    Memory targets render as hex addresses (:func:`is_memory_reference`);
    EXTERNAL-space targets — an imported symbol — render by qualified name
    through :func:`re_mcp_ghidra.helpers.describe_external` (#43).  Stack,
    register and constant targets remain unrenderable.
    """
    return is_memory_reference(ref) or is_external_address(ref.getToAddress())


def collect_xrefs_from(refs, build_item) -> tuple[list, int]:
    """Split *refs* into rendered items and a count of the non-renderable ones.

    *build_item* renders one kept reference; it is passed in because the tool's
    renderer closes over the program's ``FunctionManager``, which this module
    has no way to reach.  The whole iterable is consumed so the skipped count
    describes every reference from the address rather than one page's worth.
    """
    items: list = []
    skipped = 0
    for ref in refs:
        if not is_renderable_reference(ref):
            skipped += 1
            continue
        items.append(build_item(ref))
    return items, skipped


def external_callee(func) -> Any | None:
    """The external (imported) function *func* stands for, or ``None``.

    ``Function.getCalledFunctions()`` reports a PE import twice — the thunk at
    its stub (``ram:0x140004210``) and the external function itself
    (``EXTERNAL:0xb0``) — and an ELF import via its PLT thunk.  Both collapse
    onto the external so ``get_call_graph`` lists the import once, by name
    (#43).  An internal thunk (``_guard_dispatch_icall``) is not an import and
    is left alone.
    """
    if func.isExternal():
        return func
    if func.isThunk():
        target = func.getThunkedFunction(True)
        if target is not None and target.isExternal():
            return target
    return None


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"xrefs"})
    @session.require_open
    def get_xrefs_to(
        address: Address,
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """Get all cross-references pointing TO an address."""
        program = session.program
        ref_mgr = program.getReferenceManager()
        func_mgr = program.getFunctionManager()
        target = resolve_address(address)

        def _gen():
            refs = ref_mgr.getReferencesTo(target)
            for ref in refs:
                from_addr = ref.getFromAddress()
                func = func_mgr.getFunctionContaining(from_addr)
                ref_type = ref.getReferenceType()
                yield XrefTo(
                    from_address=format_address(from_addr.getOffset()),
                    from_function=func.getName() if func else "",
                    ref_type=str(ref_type),
                    is_call=ref_type.isCall(),
                ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"xrefs"})
    @session.require_open
    def get_xrefs_from(
        address: Address,
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> XrefsFromResult:
        """Get all cross-references FROM an address.

        References whose target is not a memory address are omitted — stack,
        register and constant targets — because rendering those offsets as hex
        is misleading; the number omitted is reported as ``skipped_non_memory``.
        A reference to an imported symbol (Ghidra's EXTERNAL space) is kept and
        rendered as ``EXTERNAL:<library>::<name>`` with ``library`` filled in.
        """
        program = session.program
        ref_mgr = program.getReferenceManager()
        func_mgr = program.getFunctionManager()
        source = resolve_address(address)

        def _render(ref) -> dict:
            to_addr = ref.getToAddress()
            ref_type = ref.getReferenceType()
            if is_external_address(to_addr):
                ext = describe_external(program, to_addr)
                return XrefFrom(
                    to_address=ext["address"],
                    to_function=ext["symbol"],
                    ref_type=str(ref_type),
                    is_call=ref_type.isCall(),
                    library=ext["library"],
                ).model_dump()
            func = func_mgr.getFunctionContaining(to_addr)
            return XrefFrom(
                to_address=format_address(to_addr.getOffset()),
                to_function=func.getName() if func else "",
                ref_type=str(ref_type),
                is_call=ref_type.isCall(),
            ).model_dump()

        items, skipped = collect_xrefs_from(ref_mgr.getReferencesFrom(source), _render)
        page = paginate_iter(items, offset, limit)
        return XrefsFromResult(**page, skipped_non_memory=skipped)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"xrefs"})
    @session.require_open
    def get_call_graph(
        address: Address,
        depth: int = 1,
    ) -> CallGraphEntry:
        """Get the call graph around a function (callers and callees).

        An imported function appears among the callees once, by name, with an
        ``EXTERNAL:<library>::<name>`` address and the memory address of its
        thunk; it has no body and is not expanded at any depth.

        Args:
            address: Function address.
            depth: Recursion depth (1-3).
        """
        if depth < 1:
            depth = 1
        if depth > 3:
            depth = 3

        func = session.program.getFunctionManager().getFunctionContaining(resolve_address(address))
        if func is None:
            from re_mcp_ghidra.exceptions import GhidraError  # noqa: PLC0415

            raise GhidraError(f"No function at {address}", error_type="NotFound")

        return _build_call_graph(func, depth, set())

    def _build_call_graph(func, depth: int, visited: set[str]) -> CallGraphEntry:
        # Keys carry the address space: an EXTERNAL slot offset must not
        # collide with a memory offset (#43).
        addr = func.getEntryPoint()
        key = str(addr)
        if key in visited or depth <= 0:
            return CallGraphEntry(
                name=func.getName(),
                address=format_address(addr.getOffset()),
            )
        visited.add(key)

        program = session.program
        ref_mgr = program.getReferenceManager()
        func_mgr = program.getFunctionManager()

        # Callers
        callers = []
        for ref in ref_mgr.getReferencesTo(addr):
            if ref.getReferenceType().isCall():
                caller_func = func_mgr.getFunctionContaining(ref.getFromAddress())
                if caller_func and str(caller_func.getEntryPoint()) not in visited:
                    if depth > 1:
                        callers.append(
                            _build_call_graph(caller_func, depth - 1, visited).model_dump()
                        )
                    else:
                        callers.append(
                            {
                                "name": caller_func.getName(),
                                "address": format_address(caller_func.getEntryPoint().getOffset()),
                            }
                        )

        # Callees.  An import shows up as its thunk and/or its external
        # function; both collapse onto one EXTERNAL entry that is never
        # expanded (it has no body).
        callees = []
        seen_external: set[str] = set()
        called = func.getCalledFunctions(None)
        if called:
            for callee in called:
                ext = external_callee(callee)
                if ext is not None:
                    entry = {
                        "name": ext.getName(),
                        **describe_external(program, ext.getEntryPoint()),
                    }
                    if entry["address"] not in seen_external:
                        seen_external.add(entry["address"])
                        callees.append(entry)
                    continue
                callee_addr = callee.getEntryPoint()
                if str(callee_addr) not in visited:
                    if depth > 1:
                        callees.append(_build_call_graph(callee, depth - 1, visited).model_dump())
                    else:
                        callees.append(
                            {
                                "name": callee.getName(),
                                "address": format_address(callee_addr.getOffset()),
                            }
                        )

        return CallGraphEntry(
            name=func.getName(),
            address=format_address(addr.getOffset()),
            callers=callers,
            callees=callees,
        )
