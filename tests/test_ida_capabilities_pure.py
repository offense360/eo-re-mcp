# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Issue #50 — ``capabilities.assembler`` recognises the ``'pc'`` processor name.

On IDA 9.x ``ida_idp.get_idp_name()`` returns ``"pc"`` for the x86/x64
module; ``"metapc"`` is the loader-side module name (``-p`` / ``processor=``).
``Session._probe_capabilities`` must accept both spellings and reject other
processors.  Runs without idalib: ``ida_idp`` and ``ida_hexrays`` are
``MagicMock`` stubs from ``conftest``.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import ida_hexrays
import ida_idp
import pytest
from re_mcp_ida.session import Session

pytestmark = pytest.mark.skipif(
    not isinstance(ida_idp, MagicMock), reason="real idalib installed; stub-only tests"
)


def _probe(monkeypatch, idp_name: str, hexrays: bool = True) -> dict[str, bool]:
    monkeypatch.setattr(ida_idp, "get_idp_name", lambda: idp_name)
    monkeypatch.setattr(ida_hexrays, "init_hexrays_plugin", lambda: hexrays)
    return Session()._probe_capabilities()


@pytest.mark.parametrize(
    ("idp_name", "expected"),
    [
        ("pc", True),  # what IDA 9.x actually reports for x86/x64
        ("metapc", True),  # module name, kept for older / future spellings
        ("arm", False),
    ],
)
def test_assembler_follows_the_processor_name(monkeypatch, idp_name, expected):
    caps = _probe(monkeypatch, idp_name)
    assert caps["assembler"] is expected


@pytest.mark.parametrize("hexrays", [True, False])
def test_decompiler_follows_hexrays_init(monkeypatch, hexrays):
    caps = _probe(monkeypatch, "pc", hexrays=hexrays)
    assert caps["decompiler"] is hexrays


def test_undo_is_always_available(monkeypatch):
    assert _probe(monkeypatch, "arm")["undo"] is True


def test_capabilities_carry_exactly_the_documented_keys(monkeypatch):
    assert set(_probe(monkeypatch, "pc")) == {"decompiler", "assembler", "undo"}
