# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Unit tests for Ghidra helpers that can run without pyghidra.

``re_mcp_ghidra.helpers`` only imports Ghidra classes lazily inside
functions, so the module itself is importable in the plain test venv.
The ``transaction()`` context manager is exercised with a fake program
object that records ``startTransaction``/``endTransaction`` calls.
"""

from __future__ import annotations

import pytest
from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    check_range_in_memory,
    to_ghidra_address,
    transaction,
    write_memory,
)
from re_mcp_ghidra.session import session as ghidra_session


class FakeProgram:
    """Records transaction calls the way ``ghidra.program.model.listing.Program`` would."""

    def __init__(self) -> None:
        self.next_id = 41
        self.calls: list[tuple] = []

    def startTransaction(self, label):
        self.next_id += 1
        self.calls.append(("start", label, self.next_id))
        return self.next_id

    def endTransaction(self, tx_id, commit):
        self.calls.append(("end", tx_id, commit))


class TestTransaction:
    def test_success_commits_once(self):
        program = FakeProgram()
        with transaction(program, "Rename function"):
            program.calls.append(("mutate",))
        assert program.calls == [
            ("start", "Rename function", 42),
            ("mutate",),
            ("end", 42, True),
        ]

    def test_ghidra_error_propagates_and_aborts(self):
        program = FakeProgram()
        with pytest.raises(GhidraError, match="nope"), transaction(program, "Set color"):
            raise GhidraError("nope", error_type="NotFound")
        assert program.calls == [("start", "Set color", 42), ("end", 42, False)]

    def test_generic_exception_propagates_and_aborts(self):
        program = FakeProgram()
        with pytest.raises(RuntimeError, match="java says no"), transaction(program, "Write bytes"):
            raise RuntimeError("java says no")
        assert program.calls == [("start", "Write bytes", 42), ("end", 42, False)]

    def test_always_aborts_on_error(self):
        """#18: a tool transaction is now the outermost one, so aborting rolls
        back only that tool's own changes."""
        program = FakeProgram()
        for exc in (GhidraError("a", error_type="X"), ValueError("b"), KeyError("c")):
            with pytest.raises(type(exc)), transaction(program, "Anything"):
                raise exc
        ends = [c for c in program.calls if c[0] == "end"]
        assert len(ends) == 3
        assert all(commit is False for _, _, commit in ends)
        assert not any(commit is True for _, _, commit in ends)

    def test_failure_logs_warning_mentioning_issue(self, caplog):
        program = FakeProgram()
        with (
            caplog.at_level("WARNING", logger="re_mcp_ghidra.helpers"),
            pytest.raises(ValueError),
            transaction(program, "Patch bytes"),
        ):
            raise ValueError("boom")
        messages = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert len(messages) == 1
        assert "Patch bytes" in messages[0]
        assert "#18" in messages[0]

    def test_failure_warning_names_exception_and_states_what_was_kept(self, caplog):
        """#14: the WARNING must say which exception fired and what happened to
        the mutations, so an operator can tell a partial change from a clean
        failure without reading the tool source.  Under #18 the answer is that
        nothing was kept."""
        program = FakeProgram()
        with (
            caplog.at_level("WARNING", logger="re_mcp_ghidra.helpers"),
            pytest.raises(ValueError),
            transaction(program, "Patch bytes"),
        ):
            raise ValueError("boom")
        messages = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert len(messages) == 1
        assert "ValueError" in messages[0]
        assert "boom" in messages[0]
        assert "rolled back" in messages[0]
        assert "nothing from this call was kept" in messages[0]

    def test_success_logs_nothing(self, caplog):
        program = FakeProgram()
        with (
            caplog.at_level("DEBUG", logger="re_mcp_ghidra.helpers"),
            transaction(program, "Quiet"),
        ):
            pass
        assert not [r for r in caplog.records if r.levelname == "WARNING"]


# ---------------------------------------------------------------------------
# check_range_in_memory / write_memory validation (#11 commit 3)
# ---------------------------------------------------------------------------


class FakeAddr:
    def __init__(self, offset: int) -> None:
        self.offset = offset

    def add(self, n: int) -> FakeAddr:
        return FakeAddr(self.offset + n)

    def getOffset(self) -> int:
        return self.offset

    def __repr__(self) -> str:
        return f"0x{self.offset:x}"


class FakeBlock:
    def __init__(
        self, start: int, end: int, *, initialized: bool = True, name: str = "blk"
    ) -> None:
        self.start, self.end, self.initialized, self.name = start, end, initialized, name

    def contains(self, addr: FakeAddr) -> bool:
        return self.start <= addr.offset <= self.end

    def getEnd(self) -> FakeAddr:
        return FakeAddr(self.end)

    def isInitialized(self) -> bool:
        return self.initialized

    def getName(self) -> str:
        return self.name


class FakeMemory:
    def __init__(self, *blocks: FakeBlock) -> None:
        self.blocks = blocks
        self.writes: list[tuple] = []

    def getBlock(self, addr: FakeAddr):
        for b in self.blocks:
            if b.contains(addr):
                return b
        return None

    def setBytes(self, addr: FakeAddr, data: bytes) -> None:
        self.writes.append((addr.offset, bytes(data)))


class FakeListing:
    def __init__(self) -> None:
        self.cleared: list[tuple] = []

    def clearCodeUnits(self, start: FakeAddr, end: FakeAddr, ctx: bool) -> None:
        self.cleared.append((start.offset, end.offset))


class FakeMemProgram(FakeProgram):
    def __init__(self, *blocks: FakeBlock) -> None:
        super().__init__()
        self.memory = FakeMemory(*blocks)
        self.listing = FakeListing()

    def getMemory(self) -> FakeMemory:
        return self.memory

    def getListing(self) -> FakeListing:
        return self.listing


class TestCheckRangeInMemory:
    def test_range_inside_one_block_passes(self):
        program = FakeMemProgram(FakeBlock(0x1000, 0x1FFF))
        check_range_in_memory(program, FakeAddr(0x1FF0), 16)

    def test_start_outside_memory_raises_not_found(self):
        program = FakeMemProgram(FakeBlock(0x1000, 0x1FFF))
        with pytest.raises(GhidraError) as ei:
            check_range_in_memory(program, FakeAddr(0x3000), 4)
        assert ei.value.error_type == "NotFound"

    def test_range_running_off_block_end_raises_not_found(self):
        program = FakeMemProgram(FakeBlock(0x1000, 0x1FFF))
        with pytest.raises(GhidraError) as ei:
            check_range_in_memory(program, FakeAddr(0x1FFE), 4)
        assert ei.value.error_type == "NotFound"

    def test_range_spanning_contiguous_blocks_passes(self):
        program = FakeMemProgram(FakeBlock(0x1000, 0x1FFF), FakeBlock(0x2000, 0x2FFF))
        check_range_in_memory(program, FakeAddr(0x1FFE), 4)

    def test_uninitialized_block_rejected_only_when_required(self):
        program = FakeMemProgram(FakeBlock(0x1000, 0x1FFF, initialized=False))
        check_range_in_memory(program, FakeAddr(0x1000), 4)
        with pytest.raises(GhidraError) as ei:
            check_range_in_memory(program, FakeAddr(0x1000), 4, initialized=True)
        assert ei.value.error_type == "InvalidArgument"


class TestWriteMemoryValidatesBeforeMutating:
    def test_invalid_range_raises_without_opening_a_transaction(self):
        program = FakeMemProgram(FakeBlock(0x1000, 0x1FFF))
        with pytest.raises(GhidraError) as ei:
            write_memory(program, FakeAddr(0x1FFE), b"\x90\x90\x90\x90")
        assert ei.value.error_type == "NotFound"
        assert program.calls == []
        assert program.listing.cleared == []
        assert program.memory.writes == []

    def test_valid_range_clears_then_writes_inside_committed_transaction(self):
        program = FakeMemProgram(FakeBlock(0x1000, 0x1FFF))
        write_memory(program, FakeAddr(0x1FFC), b"\x90\x90\x90\x90", label="Patch bytes")
        assert program.calls == [("start", "Patch bytes", 42), ("end", 42, True)]
        assert program.listing.cleared == [(0x1FFC, 0x1FFF)]
        assert program.memory.writes == [(0x1FFC, b"\x90\x90\x90\x90")]


# ---------------------------------------------------------------------------
# to_ghidra_address range/conversion guards (#28)
# ---------------------------------------------------------------------------


class FakeAddressSpace:
    """Stands in for ``ghidra.program.model.address.AddressSpace``.

    ``getMaxAddress().getOffset()`` comes back through JPype as a Java signed
    long, so a 64-bit space reports ``-1`` rather than ``0xFFFFFFFFFFFFFFFF``.
    ``getAddress`` reproduces JPype's ``OverflowError`` for Python ints that do
    not fit a Java long.
    """

    def __init__(self, max_offset: int) -> None:
        self.max_offset = max_offset
        self.calls: list[int] = []
        self.handed_out: list[FakeAddr] = []
        self.raises: Exception | None = None

    def getMaxAddress(self) -> FakeAddr:
        return FakeAddr(self.max_offset)

    def getAddress(self, offset: int) -> FakeAddr:
        self.calls.append(offset)
        if self.raises is not None:
            raise self.raises
        if not (-(2**63) <= offset < 2**63):
            raise OverflowError("int too big to convert")
        addr = FakeAddr(offset)
        self.handed_out.append(addr)
        return addr


class FakeAddressFactory:
    def __init__(self, space: FakeAddressSpace) -> None:
        self.space = space

    def getDefaultAddressSpace(self) -> FakeAddressSpace:
        return self.space


class FakeSpaceProgram:
    def __init__(self, space: FakeAddressSpace) -> None:
        self.factory = FakeAddressFactory(space)

    def getAddressFactory(self) -> FakeAddressFactory:
        return self.factory


@pytest.fixture
def open_space(monkeypatch):
    """Install a fake open program whose default space has *max_offset*."""

    def _install(max_offset: int) -> FakeAddressSpace:
        space = FakeAddressSpace(max_offset)
        monkeypatch.setattr(ghidra_session, "_program", FakeSpaceProgram(space))
        return space

    return _install


class TestToGhidraAddressRejectsOutOfRange:
    """#28: an unconvertible address must surface as a typed GhidraError.

    Before the fix, a Python int above 2**63-1 reached JPype and escaped as a
    bare ``OverflowError: int too big to convert`` — no ``error_type``, no
    address in the message, and no JSON error body for the client.
    """

    def test_in_range_offset_returns_the_space_address_unchanged(self, open_space):
        space = open_space(0xFFFFFFFF)
        addr = to_ghidra_address(0x401000)
        assert addr is space.handed_out[-1]
        assert addr.getOffset() == 0x401000
        assert space.calls == [0x401000]

    def test_offset_above_max_raises_invalid_address_from_the_range_check(self, open_space):
        space = open_space(0xFFFFFFFF)
        with pytest.raises(GhidraError) as ei:
            to_ghidra_address(0x1_0000_0000)
        assert ei.value.error_type == "InvalidAddress"
        assert "0x100000000" in str(ei.value)
        assert "outside the program's address space" in str(ei.value)
        assert "0xFFFFFFFF" in str(ei.value)
        # The range check must fire before Ghidra is asked to convert anything.
        assert space.calls == []

    def test_java_signed_max_offset_is_normalised_for_a_64bit_space(self, open_space):
        """A 64-bit space reports ``-1``; that must not reject every address."""
        space = open_space(-1)
        addr = to_ghidra_address(0x140007CC4)
        assert addr.getOffset() == 0x140007CC4
        assert space.calls == [0x140007CC4]

    @pytest.mark.parametrize("max_offset", [-1, 0xFFFFFFFFFFFFFFFF])
    def test_offset_inside_64bit_space_but_too_big_for_java_long(self, open_space, max_offset):
        """0xFFFFFFFFFFFFFFF0 is inside a 64-bit space, so the range check
        passes and only the try/except around ``getAddress`` can catch it."""
        space = open_space(max_offset)
        with pytest.raises(GhidraError) as ei:
            to_ghidra_address(0xFFFFFFFFFFFFFFF0)
        assert ei.value.error_type == "InvalidAddress"
        assert "0xFFFFFFFFFFFFFFF0" in str(ei.value)
        assert "int too big to convert" in str(ei.value)
        assert space.calls == [0xFFFFFFFFFFFFFFF0]

    def test_negative_offset_raises_invalid_address_with_a_readable_message(self, open_space):
        space = open_space(-1)
        with pytest.raises(GhidraError) as ei:
            to_ghidra_address(-1)
        assert ei.value.error_type == "InvalidAddress"
        assert "-0x1" in str(ei.value)
        assert "0x-1" not in str(ei.value)
        assert space.calls == []

    def test_ghidra_error_from_get_address_is_not_rewrapped(self, open_space):
        space = open_space(0xFFFFFFFF)
        space.raises = GhidraError("space said no", error_type="NotFound")
        with pytest.raises(GhidraError) as ei:
            to_ghidra_address(0x1000)
        assert ei.value is space.raises
        assert ei.value.error_type == "NotFound"

    def test_no_open_database_still_reports_no_database(self, monkeypatch):
        monkeypatch.setattr(ghidra_session, "_program", None)
        with pytest.raises(GhidraError) as ei:
            to_ghidra_address(0x1000)
        assert ei.value.error_type == "NoDatabase"
