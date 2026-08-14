"""AST node definitions for UDM search (YARA-L search dialect) queries.

Produced by :mod:`nudm.parser` from the PEG grammar in :mod:`nudm.grammar`.
Consumed by :mod:`nudm.duckdb_sql` to generate DuckDB SQL.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Union


# ---------------------------------------------------------------------------
# Expressions
# ---------------------------------------------------------------------------

class Expr:
    """Base class for all expression nodes."""


@dataclass
class FieldRef(Expr):
    """A UDM field reference, e.g. ``principal.user.userid``,
    ``$e.target.ip``, ``additional.fields["pod_name"]`` or
    ``security_result[0].description``.

    ``prefix`` is the event-variable prefix (usually ``e``) or ``None``.
    ``segments`` is the dotted path; a segment is a field name (``str``),
    a list index (``int``) or a map key (``Key``).
    """
    segments: tuple[Union[str, int, "Key"], ...]
    prefix: Optional[str] = None

    @property
    def path(self) -> str:
        """Canonical dotted path, without any ``$`` prefix."""
        out: list[str] = []
        for seg in self.segments:
            if isinstance(seg, Key):
                out[-1] += f"[{seg.value!r}]"
            elif isinstance(seg, int):
                out[-1] += f"[{seg}]"
            else:
                out.append(seg)
        return ".".join(out)


@dataclass(frozen=True)
class Key:
    """A bracketed string key accessor, e.g. ``["pod_name"]``."""
    value: str


@dataclass
class VarRef(Expr):
    """A placeholder variable reference, e.g. ``$userid``."""
    name: str


@dataclass
class Literal(Expr):
    """A literal value. ``kind`` is one of ``string``, ``regex``, ``number``,
    ``boolean``, ``bare`` (unquoted word) or ``template`` (``${var}``)."""
    value: object
    kind: str


@dataclass
class ListRef(Expr):
    """A reference-list / data-table reference, e.g. ``%badApps.hostname``."""
    table: str
    column: Optional[str] = None


@dataclass
class FuncCall(Expr):
    """A function call, e.g. ``timestamp.get_date(x, "UTC")`` or an
    aggregate such as ``count(metadata.id)`` in an outcome section."""
    name: str  # dotted name, lowercased, e.g. "timestamp.get_date"
    args: tuple[Expr, ...]


@dataclass
class Comparison(Expr):
    """``left op right [nocase]``, optionally quantified with ``any``."""
    left: Expr
    op: str           # =, !=, <, >, <=, >=, in
    right: Expr
    nocase: bool = False
    quantifier: Optional[str] = None  # "any" or None


@dataclass
class Not(Expr):
    child: Expr


@dataclass
class And(Expr):
    children: tuple[Expr, ...]


@dataclass
class Or(Expr):
    children: tuple[Expr, ...]


@dataclass
class Assign(Expr):
    """Placeholder assignment: ``$var = <field path | function call>``."""
    name: str
    value: Expr


# ---------------------------------------------------------------------------
# Query sections
# ---------------------------------------------------------------------------

@dataclass
class TimeGrain:
    """Time granularity on a match item: ``[by|over every] [first] [N] unit
    [before|after $pivot]``."""
    unit: str                 # minute, hour, day, week, month
    quantity: int = 1
    first: bool = False       # group by range start only
    anchor: Optional[str] = None   # "before" | "after" | None (plain tumbling window)
    pivot: Optional[str] = None    # the event-variable name the window is anchored to


@dataclass
class MatchItem:
    expr: Expr                # FieldRef or VarRef
    grain: Optional[TimeGrain] = None


@dataclass
class OrderItem:
    expr: Expr                # VarRef or FieldRef
    direction: str = "asc"    # asc | desc


@dataclass
class Query:
    """Root node of a parsed UDM search query."""
    events: tuple[Expr, ...] = ()        # Assign | bool-expr nodes, in order
    match: tuple[MatchItem, ...] = ()
    outcome: tuple[Assign, ...] = ()
    dedup: tuple[Expr, ...] = ()
    order: tuple[OrderItem, ...] = ()
    limit: Optional[int] = None

    @property
    def assignments(self) -> dict[str, Expr]:
        return {s.name: s.value for s in self.events if isinstance(s, Assign)}

    @property
    def where(self) -> Optional[Expr]:
        """All non-assignment event expressions, AND-combined."""
        terms = [s for s in self.events if not isinstance(s, Assign)]
        if not terms:
            return None
        if len(terms) == 1:
            return terms[0]
        return And(tuple(terms))
