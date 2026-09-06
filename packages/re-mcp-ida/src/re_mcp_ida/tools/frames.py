# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Stack frame and local variable analysis tools."""

from __future__ import annotations

import ida_frame
import ida_funcs
import ida_nalt
import ida_typeinf
import idc
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ida.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    META_DECOMPILER,
    Address,
    IDAError,
    decode_insn_at,
    decompile_at,
    format_address,
    get_func_name,
    resolve_address,
    resolve_function,
)
from re_mcp_ida.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class FrameMember(BaseModel):
    """Stack frame member."""

    offset: int = Field(description="Frame offset.")
    name: str = Field(description="Member name.")
    size: int = Field(description="Member size in bytes.")


class FrameDetail(BaseModel):
    """Stack frame details."""

    frame_size: int = Field(description="Total frame size.")
    local_size: int = Field(description="Local variable area size.")
    saved_regs_size: int = Field(description="Saved registers area size.")
    args_size: int = Field(description="Arguments area size.")
    member_count: int = Field(description="Number of frame members.")
    members: list[FrameMember] = Field(description="Frame members.")


class GetStackFrameResult(BaseModel):
    """Stack frame for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    frame: FrameDetail | None = Field(description="Frame details, or null if no frame.")


class FunctionVariable(BaseModel):
    """A decompiler variable."""

    name: str = Field(description="Variable name.")
    type: str = Field(description="Variable type.")
    is_arg: bool = Field(description="Whether this is a function argument.")
    is_result: bool = Field(description="Whether this is the return value.")
    width: int = Field(description="Variable width in bytes.")


class GetFunctionVarsResult(BaseModel):
    """Function variables from the decompiler."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    variable_count: int = Field(description="Number of variables.")
    variables: list[FunctionVariable] = Field(description="Variable list.")


class StackDeltaResult(BaseModel):
    """Result of a stack delta override."""

    function: str = Field(description="Function address (hex).")
    address: str = Field(description="Address of the instruction (hex).")
    applies_at: str = Field(
        description="Address of the stack point: the end of the instruction (hex)."
    )
    old_delta: int = Field(description="Previous SP delta at the stack point.")
    delta: int | None = Field(default=None, description="New SP delta (null when deleted).")
    sp_value: int = Field(description="SP value at the stack point after the change.")


def stack_point_ea(ea: int) -> int:
    """Address of the stack point for the instruction at *ea*.

    IDA records SP changes at the *end* of the instruction that causes them
    (``insn.ea + insn.size``); a point added at the instruction start would land
    on the previous instruction's point instead (issue #6).
    """
    insn = decode_insn_at(ea)
    return insn.ea + insn.size


def delete_user_stack_point(func: ida_funcs.func_t, ea: int) -> int:
    """Delete the user stack point of the instruction at *ea*, returning its address.

    Refuses (``NotFound``) unless the point was added by the user: ``del_stkpnt``
    would just as happily delete IDA's own point, and nothing short of
    re-creating the instruction brings that back.
    """
    sp_ea = stack_point_ea(ea)
    if not ida_nalt.is_usersp(sp_ea):
        raise IDAError(
            f"No user stack delta at {format_address(sp_ea)} "
            "(IDA's own stack points are not deleted)",
            error_type="NotFound",
        )
    if not ida_frame.del_stkpnt(func, sp_ea):
        raise IDAError(
            f"del_stkpnt failed at {format_address(sp_ea)}", error_type="OperationFailed"
        )
    return sp_ea


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"functions"},
    )
    @session.require_open
    def get_stack_frame(
        address: Address,
    ) -> GetStackFrameResult:
        """Get the stack frame layout of a function (offsets, sizes, no Hex-Rays needed).

        For typed variable info from decompilation, use get_function_vars.

        Args:
            address: Address or name of the function.
        """
        func = resolve_function(address)

        frame_tif = ida_typeinf.tinfo_t()
        if not frame_tif.get_func_frame(func):
            return GetStackFrameResult(
                function=format_address(func.start_ea),
                name=get_func_name(func.start_ea),
                frame=None,
            )

        udt = ida_typeinf.udt_type_data_t()
        frame_tif.get_udt_details(udt)

        members = []
        for udm in udt:
            if udm.is_gap():
                continue
            byte_offset = udm.offset // 8
            members.append(
                FrameMember(
                    offset=byte_offset,
                    name=udm.name or f"var_{byte_offset:X}",
                    size=udm.size // 8,
                )
            )

        return GetStackFrameResult(
            function=format_address(func.start_ea),
            name=get_func_name(func.start_ea),
            frame=FrameDetail(
                frame_size=idc.get_func_attr(func.start_ea, idc.FUNCATTR_FRSIZE),
                local_size=func.frsize,
                saved_regs_size=func.frregs,
                args_size=func.argsize,
                member_count=len(members),
                members=members,
            ),
        )

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"functions", "decompiler"},
        meta=META_DECOMPILER,
    )
    @session.require_open
    def get_function_vars(
        address: Address,
    ) -> GetFunctionVarsResult:
        """Get typed locals/params via Hex-Rays decompilation (for raw frame use get_stack_frame).

        Args:
            address: Address or name of the function.
        """
        cfunc, func = decompile_at(address)

        variables = [
            FunctionVariable(
                name=lvar.name,
                type=str(lvar.type()),
                is_arg=lvar.is_arg_var,
                is_result=lvar.is_result_var,
                width=lvar.width,
            )
            for lvar in cfunc.lvars
        ]

        return GetFunctionVarsResult(
            function=format_address(func.start_ea),
            name=get_func_name(func.start_ea),
            variable_count=len(variables),
            variables=variables,
        )

    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"functions", "modification"},
    )
    @session.require_open
    def set_stack_delta(
        address: Address,
        delta: int,
    ) -> StackDeltaResult:
        """Override the stack pointer delta at an address (the fix for "positive sp value").

        IDA tracks how each instruction moves SP; when it gets that wrong the function
        gets a broken frame and Hex-Rays refuses or produces nonsense. Pin the correct
        delta here, then call refresh_decompilation on the function. The point replaces
        IDA's own point for that instruction; undo with delete_stack_delta.

        Args:
            address: Address of the instruction whose SP effect is wrong; the delta is
                recorded at the end of that instruction (`ea + size`), where IDA keeps
                stack points.
            delta: Correct SP delta for that instruction (bytes, negative for a push).
        """
        ea = resolve_address(address)
        func = resolve_function(ea)

        sp_ea = stack_point_ea(ea)
        old_delta = ida_frame.get_sp_delta(func, sp_ea)
        if not ida_frame.add_user_stkpnt(sp_ea, delta):
            raise IDAError(
                f"add_user_stkpnt failed at {format_address(sp_ea)}",
                error_type="OperationFailed",
            )

        return StackDeltaResult(
            function=format_address(func.start_ea),
            address=format_address(ea),
            applies_at=format_address(sp_ea),
            old_delta=old_delta,
            delta=delta,
            sp_value=ida_frame.get_spd(func, sp_ea),
        )

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"functions", "modification"},
    )
    @session.require_open
    def delete_stack_delta(
        address: Address,
    ) -> StackDeltaResult:
        """Remove a set_stack_delta override; IDA's own stack points are never deleted.

        Only user stack points are removed (NotFound otherwise). IDA does not recreate
        the automatic point the override replaced; to get the instruction's own SP
        effect back, re-create the instruction (undefine, make_code) and run
        analyze_database so IDA re-emulates it.

        Args:
            address: Address of the instruction whose override should be dropped.
        """
        ea = resolve_address(address)
        func = resolve_function(ea)

        sp_ea = stack_point_ea(ea)
        old_delta = ida_frame.get_sp_delta(func, sp_ea)
        delete_user_stack_point(func, ea)

        return StackDeltaResult(
            function=format_address(func.start_ea),
            address=format_address(ea),
            applies_at=format_address(sp_ea),
            old_delta=old_delta,
            sp_value=ida_frame.get_spd(func, sp_ea),
        )
