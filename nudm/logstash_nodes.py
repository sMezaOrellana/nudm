"""AST node definitions for the SecOps parser dialect (the logstash-like
``filter { ... }`` language used by Chronicle parsers / code snippets).

Produced by :mod:`nudm.logstash_parser` from the PEG grammar in
:mod:`nudm.logstash_grammar`. Consumed by the interpreter in
:mod:`nudm.logstash_exec`.

Unlike the UDM query and YARA-L dialects, argument values carry no
expression semantics at parse time (they're plain strings/numbers/booleans/
arrays/hashes, with ``%{token}`` interpolation deferred to execution), so
only statements and conditionals need dedicated node types.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Union

# Argument values as parsed: strings, numbers, booleans, arrays of values,
# hashes (dicts) of string -> value.
Value = Union[str, int, float, bool, list, dict]


# ---------------------------------------------------------------------------
# Statements
# ---------------------------------------------------------------------------

class Stmt:
    """Base class for statements inside a ``filter { ... }`` block."""


@dataclass
class PluginCall(Stmt):
    """One plugin invocation, e.g. ``grok { match => {...} on_error => "f" }``.

    ``args`` preserves declaration order (Python dict order).
    """
    name: str
    args: dict[str, Value]


@dataclass
class IfStmt(Stmt):
    """``if cond { ... } [else if cond { ... }] [else { ... }]``.

    An ``else if`` chain is represented by ``else_body`` containing a single
    nested :class:`IfStmt`.
    """
    cond: "CondExpr"
    then_body: tuple[Stmt, ...]
    else_body: Optional[tuple[Stmt, ...]] = None


@dataclass
class ForStmt(Stmt):
    """``for [index,] item in token [map] { ... }``.

    ``loop_vars`` has one or two names. ``is_map`` is the trailing ``map``
    keyword (key/value iteration over an object).
    """
    loop_vars: tuple[str, ...]
    iterable: str
    is_map: bool
    body: tuple[Stmt, ...]


@dataclass
class Parser:
    """Root node: the ``filter { ... }`` block and its statements."""
    statements: tuple[Stmt, ...]


# ---------------------------------------------------------------------------
# Conditionals (if statements only -- the parser language has no other
# boolean-expression surface)
# ---------------------------------------------------------------------------

class CondExpr:
    """Base class for conditional expressions."""


@dataclass
class FieldRef(CondExpr):
    """A bracketed field reference, e.g. ``[action]``, ``[network][source][hostname]``."""
    segments: tuple[str, ...]

    @property
    def path(self) -> str:
        return "".join(f"[{s}]" for s in self.segments)


@dataclass
class Literal(CondExpr):
    """A literal operand: string, number or boolean."""
    value: object


@dataclass
class ArrayLit(CondExpr):
    """An array operand, e.g. the right side of ``in ["tcp", "udp"]``."""
    items: tuple[object, ...]


@dataclass
class Comparison(CondExpr):
    """``left op right`` where op is one of
    ``== != < > <= >= =~ !~ in``."""
    left: CondExpr
    op: str
    right: CondExpr


@dataclass
class Not(CondExpr):
    child: CondExpr


@dataclass
class And(CondExpr):
    children: tuple[CondExpr, ...]


@dataclass
class Or(CondExpr):
    children: tuple[CondExpr, ...]
