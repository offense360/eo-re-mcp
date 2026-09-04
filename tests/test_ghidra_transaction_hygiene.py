# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Guard against validation raises inside Ghidra ``with transaction(...)`` blocks (#14).

Validate before mutate keeps error messages clear and the undo history
clean (#18); it is no longer a data-safety requirement (#11 is obsolete).
Since #18 the session keeps no standing transaction, so a tool transaction
is the outermost one and ``helpers.transaction()`` aborts it when the body
raises: nothing from a failed call survives.  But an abort still logs a
WARNING and costs a rolled-back transaction, and a raise that comes from
inside the block is a Java exception rather than a ``GhidraError`` with a
useful message.  So a tool must do its pure validation (lookups,
``isinstance``, ``is None``, argument parsing) *before* entering the block.

This test parses every ``re_mcp_ghidra.tools`` module with ``ast`` (no JVM
needed) and flags a ``raise`` inside a ``with transaction(...)`` body that
can execute before any mutating call.  The static rule is deliberately
simple and conservative:

* A call is *pure* when it is a builtin / core helper listed in
  ``PURE_NAMES``, a constructor (``CapitalizedName(...)``), or a method
  whose name starts with one of ``READ_PREFIXES`` (``get``, ``is``, ``has``,
  ...).  ``parse`` is treated as a read here even though ``CParser.parse``
  can add types to the DataTypeManager -- that impurity was tracked in #13
  (closed by #18: the abort now rolls those types back) and the affected
  tools are listed in ``ALLOWED``.
* Every other call is assumed to mutate.  Once a mutating call has been
  seen on a path, later raises on that path are legitimate (that is the
  case the WARNING exists for).
* Statements are walked in order; ``if``/``for``/``while``/``try``/``with``
  branches are entered with the mutation state at their head.  A raise
  reached while nothing has mutated yet is a violation.

Unknown calls count as mutating, so the rule under-reports rather than
over-reports.  Sites that genuinely cannot validate first belong in
``ALLOWED`` with the issue that explains them, never in a file-level opt-out.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

TOOLS_DIR = (
    pathlib.Path(__file__).resolve().parent.parent
    / "packages"
    / "re-mcp-ghidra"
    / "src"
    / "re_mcp_ghidra"
    / "tools"
)

# ``module.function`` -> reason.  Every entry must still trip the rule, so a
# stale entry fails the test and gets removed when its issue is fixed.
ALLOWED: dict[str, str] = {
    # CParser.parse() may add intermediate types to the DTM before returning
    # None; the null check cannot precede the parser run.  Harmless since #18
    # (the abort rolls the types back), but the rule still trips here.
    "types.parse_type_declaration": "#13 (closed by #18: partial changes now roll back)",
    "srclang.parse_source_declarations": "#13 (closed by #18: partial changes now roll back)",
}

PURE_NAMES = frozenset(
    {
        "isinstance",
        "issubclass",
        "len",
        "str",
        "int",
        "float",
        "bool",
        "bytes",
        "list",
        "dict",
        "set",
        "tuple",
        "range",
        "enumerate",
        "sorted",
        "reversed",
        "min",
        "max",
        "abs",
        "hex",
        "repr",
        "hasattr",
        "getattr",
        "format_address",
        "resolve_address",
        "resolve_function",
    }
)

READ_PREFIXES = (
    "get",
    "is",
    "has",
    "contains",
    "find",
    "next",
    "equals",
    "to",
    "size",
    "length",
    "parse",  # see module docstring and ALLOWED
)


def _is_pure_call(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id in PURE_NAMES or func.id[:1].isupper()
    if isinstance(func, ast.Attribute):
        return func.attr.startswith(READ_PREFIXES)
    return False


def _mutates(node: ast.AST) -> bool:
    """True if any call under ``node`` is not known to be pure."""
    return any(isinstance(sub, ast.Call) and not _is_pure_call(sub) for sub in ast.walk(node))


def _block_mutates(stmts: list[ast.stmt]) -> bool:
    return any(_mutates(stmt) for stmt in stmts)


def _raises_before_mutation(stmts: list[ast.stmt], mutated: bool) -> list[int]:
    """Line numbers of ``raise`` statements reachable before any mutating call."""
    hits: list[int] = []
    for stmt in stmts:
        if isinstance(stmt, ast.Raise):
            if not mutated:
                hits.append(stmt.lineno)
            continue
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(stmt, ast.If):
            head = mutated or _mutates(stmt.test)
            hits += _raises_before_mutation(stmt.body, head)
            hits += _raises_before_mutation(stmt.orelse, head)
        elif isinstance(stmt, ast.For):
            head = mutated or _mutates(stmt.iter)
            hits += _raises_before_mutation(stmt.body, head)
            hits += _raises_before_mutation(stmt.orelse, head)
        elif isinstance(stmt, ast.While):
            head = mutated or _mutates(stmt.test)
            hits += _raises_before_mutation(stmt.body, head)
            hits += _raises_before_mutation(stmt.orelse, head)
        elif isinstance(stmt, ast.With):
            head = mutated or any(_mutates(item.context_expr) for item in stmt.items)
            hits += _raises_before_mutation(stmt.body, head)
        elif isinstance(stmt, ast.Try):
            hits += _raises_before_mutation(stmt.body, mutated)
            after_body = mutated or _block_mutates(stmt.body)
            for handler in stmt.handlers:
                hits += _raises_before_mutation(handler.body, after_body)
            hits += _raises_before_mutation(stmt.orelse, after_body)
            hits += _raises_before_mutation(stmt.finalbody, after_body)
        mutated = mutated or _mutates(stmt)
    return hits


def _transaction_label(node: ast.With) -> str | None:
    """Return the label if ``node`` is ``with transaction(program, label)``, else None."""
    for item in node.items:
        call = item.context_expr
        if (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "transaction"
        ):
            label = call.args[1] if len(call.args) > 1 else None
            return label.value if isinstance(label, ast.Constant) else "?"
    return None


def _walk_with_function(node: ast.AST, func_name: str):
    """Yield ``(innermost_function_name, With)`` for every With under ``node``."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield from _walk_with_function(child, child.name)
            continue
        if isinstance(child, ast.With):
            yield func_name, child
        yield from _walk_with_function(child, func_name)


def _iter_transaction_blocks():
    """Yield ``(path, function, label, lineno, body)`` for every transaction block.

    The function is the innermost enclosing ``def`` -- the tool, not the
    ``register(mcp)`` wrapper it is defined in.
    """
    for path in sorted(TOOLS_DIR.glob("*.py")):
        if path.name.startswith("_"):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for func_name, node in _walk_with_function(tree, "<module>"):
            label = _transaction_label(node)
            if label is None:
                continue
            yield path, func_name, label, node.lineno, node.body


def _collect() -> tuple[list[str], set[str]]:
    violations: list[str] = []
    tripped: set[str] = set()
    for path, func_name, label, lineno, body in _iter_transaction_blocks():
        key = f"{path.stem}.{func_name}"
        lines = _raises_before_mutation(body, mutated=False)
        if not lines:
            continue
        tripped.add(key)
        if key in ALLOWED:
            continue
        violations.append(
            f"  {path.name}:{lineno} {func_name} ({label!r}): "
            f"raise at line(s) {', '.join(map(str, lines))} before any mutation"
        )
    return violations, tripped


def test_transaction_blocks_are_found():
    blocks = list(_iter_transaction_blocks())
    assert len(blocks) > 40, "parser regression: transaction blocks not found"


def test_no_validation_raise_inside_transaction():
    violations, _ = _collect()
    if violations:
        pytest.fail(
            "Validation raised inside `with transaction(...)` before any mutation "
            "(#14). Move the check above the block so the helper WARNING only "
            "fires for real partial changes:\n" + "\n".join(violations)
        )


def test_allowlist_entries_are_still_needed():
    _, tripped = _collect()
    stale = sorted(set(ALLOWED) - tripped)
    assert not stale, f"ALLOWED entries no longer trip the rule; remove them: {stale}"
