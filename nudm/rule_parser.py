"""PEG parser for full YARA-L 2.0 rules: text -> :class:`nudm.rule_nodes.Rule`.

Reuses the tree-walking helpers and section builders from :mod:`nudm.parser`
wherever the underlying grammar rule is identical between the two dialects
(``body``/``match_list``/``outcome_list`` etc. -- see
:mod:`nudm.rule_grammar`). Only ``condition:`` needs its own builders,
since it has no equivalent in the plain UDM query dialect.
"""
from __future__ import annotations

from parsimonious.exceptions import ParseError as ParsimoniousParseError
from parsimonious.grammar import Grammar
from parsimonious.nodes import Node

from .rule_grammar import RULE_GRAMMAR
from .rule_nodes import EventCount, EventRef, Rule
from .nodes import And, Assign, Comparison, Expr, MatchItem, Not, Or, VarRef
from .parser import (
    _build_assign_item,
    _build_events,
    _build_literal,
    _build_match,
    _build_variable,
    _child,
    _children,
    _inner,
    _named,
)

_GRAMMAR = Grammar(RULE_GRAMMAR)


class UDMRuleError(ValueError):
    """Raised when a YARA-L rule can't be parsed."""


def parse_rule(text: str) -> Rule:
    """Parse a full YARA-L 2.0 rule (``rule name { ... }``) into a
    :class:`~nudm.rule_nodes.Rule` AST."""
    try:
        tree = _GRAMMAR.parse(text)
    except ParsimoniousParseError as exc:  # noqa: TRY003
        line = text.count("\n", 0, exc.pos) + 1
        col = exc.pos - text.rfind("\n", 0, exc.pos)
        raise UDMRuleError(
            f"Syntax error at line {line}, column {col}: "
            f"expected {exc.expr.name if exc.expr else '?'} near "
            f"{text[exc.pos:exc.pos + 20]!r}"
        ) from exc
    return _build_rule(tree)


# ---------------------------------------------------------------------------
# Rule / meta / options
# ---------------------------------------------------------------------------

def _build_rule(node: Node) -> Rule:
    name = _child(node, "ident").text
    meta: dict[str, object] = {}
    events: list[Expr] = []
    match: list[MatchItem] = []
    outcome: list[Assign] = []
    condition: Expr | None = None
    options: dict[str, object] = {}

    for sec in _named(node):
        if sec.expr_name == "meta_sec":
            meta = _build_kv_items(_child(sec, "meta_list"), "meta_item")
        elif sec.expr_name == "rule_events_sec":
            events = _build_events(sec)
        elif sec.expr_name == "match_sec":
            match = _build_match(sec)
        elif sec.expr_name == "outcome_sec":
            outcome = [_build_assign_item(i)
                       for i in _children(_child(sec, "outcome_list"), "outcome_item")]
        elif sec.expr_name == "condition_sec":
            condition = _build_cond_or(_child(sec, "cond_or_expr"))
        elif sec.expr_name == "options_sec":
            options = _build_kv_items(_child(sec, "options_list"), "options_item")

    if condition is None:
        raise UDMRuleError(f"Rule {name!r} has no condition: section")
    return Rule(name=name, meta=meta, events=tuple(events), match=tuple(match),
                outcome=tuple(outcome), condition=condition, options=options)


def _build_kv_items(list_node: Node | None, item_name: str) -> dict[str, object]:
    """Shared builder for ``meta:``/``options:``: both are just
    ``ident = literal`` lists."""
    out: dict[str, object] = {}
    if list_node is None:
        return out
    for item in _children(list_node, item_name):
        key = _child(item, "ident").text
        out[key] = _build_literal(_inner(_child(item, "literal"))).value
    return out


# ---------------------------------------------------------------------------
# condition:
# ---------------------------------------------------------------------------

def _build_cond_or(node: Node) -> Expr:
    terms = [_build_cond_and(c) for c in _children(node, "cond_and_expr")]
    if len(terms) == 1:
        return terms[0]
    return Or(tuple(terms))


def _build_cond_and(node: Node) -> Expr:
    terms = [_build_cond_unary(c) for c in _children(node, "cond_unary")]
    if len(terms) == 1:
        return terms[0]
    return And(tuple(terms))


def _build_cond_unary(node: Node) -> Expr:
    # cond_unary = cond_not_op cond_unary / "(" _ cond_or_expr ")" / cond_atom
    if _child(node, "cond_not_op") is not None:
        return Not(_build_cond_unary(_children(node, "cond_unary")[0]))
    if (or_node := _child(node, "cond_or_expr")) is not None:
        return _build_cond_or(or_node)
    return _build_cond_atom(_child(node, "cond_atom"))


def _build_cond_atom(node: Node) -> Expr:
    # cond_atom = cond_comparison / event_count / variable
    if (cmp := _child(node, "cond_comparison")) is not None:
        return _build_cond_comparison(cmp)
    if (ec := _child(node, "event_count")) is not None:
        return EventCount(name=_event_count_name(ec))
    # a bare "$var": is this event variable present at all?
    return EventRef(name=_build_variable(_child(node, "variable")))


def _build_cond_comparison(node: Node) -> Comparison:
    left, right = (_build_cond_operand(o) for o in _children(node, "cond_operand"))
    op = _child(node, "op").text.strip().lower()
    return Comparison(left=left, op=op, right=right)


def _build_cond_operand(node: Node) -> Expr:
    # cond_operand = event_count / variable / literal
    if (ec := _child(node, "event_count")) is not None:
        return EventCount(name=_event_count_name(ec))
    if (var := _child(node, "variable")) is not None:
        # Nested inside a comparison, "$x" means "the outcome variable x",
        # unlike the bare top-level case in _build_cond_atom (EventRef).
        return VarRef(name=_build_variable(var))
    return _build_literal(_inner(_child(node, "literal")))


def _event_count_name(node: Node) -> str:
    # event_count = "#" ident
    return _child(node, "ident").text
