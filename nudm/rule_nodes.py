"""AST additions for full YARA-L 2.0 rules, on top of :mod:`nudm.nodes`.

Everything about a rule's ``events:``/``match:``/``outcome:`` sections
reuses the existing node types (:class:`~nudm.nodes.Assign`,
:class:`~nudm.nodes.Comparison`, :class:`~nudm.nodes.And`/``Or``/``Not``,
:class:`~nudm.nodes.FieldRef`, :class:`~nudm.nodes.MatchItem`, ...)
unchanged. Only ``condition:`` needs new operand types, since it reasons
about *event variables* rather than field values.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .nodes import Assign, Expr, MatchItem


@dataclass
class EventRef(Expr):
    """``$var`` used bare in a ``condition:`` expression: true if the event
    variable ``var`` matched at least one (joined) row."""
    name: str


@dataclass
class EventCount(Expr):
    """``#var`` in a ``condition:`` expression: the count of distinct
    matched rows for event variable ``var``."""
    name: str


@dataclass
class Rule:
    """Root node of a parsed YARA-L 2.0 rule."""
    name: str
    meta: dict[str, object] = None
    events: tuple[Expr, ...] = ()          # same shape as Query.events
    match: tuple[MatchItem, ...] = ()
    outcome: tuple[Assign, ...] = ()
    condition: Optional[Expr] = None
    options: dict[str, object] = None

    def __post_init__(self):
        if self.meta is None:
            self.meta = {}
        if self.options is None:
            self.options = {}
