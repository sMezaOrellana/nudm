"""PEG parser for UDM search queries: text -> :class:`nudm.nodes.Query` AST.

Uses :mod:`parsimonious` with the PEG grammar from :mod:`nudm.grammar`.
"""
from __future__ import annotations

from parsimonious.exceptions import ParseError as ParsimoniousParseError
from parsimonious.grammar import Grammar
from parsimonious.nodes import Node

from .grammar import GRAMMAR
from .nodes import (
    And,
    Assign,
    Comparison,
    Expr,
    FieldRef,
    FuncCall,
    Key,
    ListRef,
    Literal,
    MatchItem,
    Not,
    Or,
    OrderItem,
    Query,
    TimeGrain,
    VarRef,
)

_GRAMMAR = Grammar(GRAMMAR)


class UDMQueryError(ValueError):
    """Raised when a UDM search query cannot be parsed."""


def parse(text: str) -> Query:
    """Parse a UDM search query string into a :class:`Query` AST."""
    try:
        tree = _GRAMMAR.parse(text)
    except ParsimoniousParseError as exc:  # noqa: TRY003
        line = text.count("\n", 0, exc.pos) + 1
        col = exc.pos - text.rfind("\n", 0, exc.pos)
        raise UDMQueryError(
            f"Syntax error at line {line}, column {col}: "
            f"expected {exc.expr.name if exc.expr else '?'} near "
            f"{text[exc.pos:exc.pos + 20]!r}"
        ) from exc
    return _build_query(tree)


# ---------------------------------------------------------------------------
# Generic tree helpers
# ---------------------------------------------------------------------------

def _named(node: Node) -> list[Node]:
    """Named grammar-rule nodes reachable from ``node`` without passing
    through another named node.

    Parsimonious wraps quantified (``?``/``*``) and sequence expressions in
    extra unnamed nodes, so a rule's named children are not always direct
    children of the rule's node; this descends through those wrappers while
    stopping at (and not descending past) each named node it finds.
    """
    out: list[Node] = []
    for c in node.children:
        if c.expr_name:
            out.append(c)
        else:
            out.extend(_named(c))
    return out


def _inner(node: Node) -> Node:
    """The single named child of a wrapper/chain rule."""
    return _named(node)[0]


def _child(node: Node, name: str) -> Node | None:
    for c in _named(node):
        if c.expr_name == name:
            return c
    return None


def _children(node: Node, name: str) -> list[Node]:
    return [c for c in _named(node) if c.expr_name == name]


def _digits(node: Node) -> str:
    """Text of the first unnamed numeric token among direct children."""
    for c in node.children:
        if not c.expr_name and c.text.strip().isdigit():
            return c.text.strip()
    raise UDMQueryError(f"Expected a number in {node.text!r}")


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _build_query(node: Node) -> Query:
    events: list[Expr] = []
    match: list[MatchItem] = []
    outcome: list[Assign] = []
    dedup: list[Expr] = []
    order: list[OrderItem] = []
    limit: int | None = None

    for sec in _named(node):
        if sec.expr_name == "events_sec":
            events = _build_events(sec)
        elif sec.expr_name == "match_sec":
            match = _build_match(sec)
        elif sec.expr_name == "outcome_sec":
            outcome = [_build_assign_item(i)
                       for i in _children(_child(sec, "outcome_list"), "outcome_item")]
        elif sec.expr_name == "dedup_sec":
            dedup = [_build_ref(i) for i in _children(_child(sec, "ref_list"), "ref_item")]
        elif sec.expr_name == "order_sec":
            order = [_build_order_item(i)
                     for i in _children(_child(sec, "order_list"), "order_item")]
        elif sec.expr_name == "limit_sec":
            limit = int(_digits(sec))
    return Query(events=tuple(events), match=tuple(match), outcome=tuple(outcome),
                 dedup=tuple(dedup), order=tuple(order), limit=limit)


def _build_events(node: Node) -> list[Expr]:
    body = _child(node, "body")
    if body is None:
        return []
    return [_build_line(l) for l in _children(body, "line")]


def _build_line(node: Node) -> Expr:
    inner = _inner(node)
    if inner.expr_name == "assign":
        var = _child(inner, "variable")
        rhs = _inner(_child(inner, "assign_rhs"))
        return Assign(name=_build_variable(var), value=_build_expr_node(rhs))
    return _build_or(inner)


def _build_match(node: Node) -> list[MatchItem]:
    lst = _child(node, "match_list")
    items = []
    for item in _children(lst, "match_item"):
        expr_node = _inner(_child(item, "match_expr"))
        grain_node = _child(item, "time_grain")
        grain = None
        if grain_node is not None:
            qty = _child(grain_node, "grain_qty")
            unit = _child(grain_node, "grain_unit").text.lower()
            unit = {
                "m": "minute", "min": "minute", "mins": "minute", "minutes": "minute",
                "h": "hour", "hr": "hour", "hrs": "hour", "hours": "hour",
                "d": "day", "days": "day",
                "w": "week", "wk": "week", "wks": "week", "weeks": "week",
                "mo": "month", "mos": "month", "months": "month",
            }.get(unit, unit)
            anchor_node = _child(grain_node, "anchor_clause")
            anchor = pivot = None
            if anchor_node is not None:
                anchor = _child(anchor_node, "anchor_dir").text.lower()
                pivot = _build_variable(_child(anchor_node, "variable"))
            grain = TimeGrain(unit=unit,
                              quantity=int(qty.text.strip()) if qty else 1,
                              first=_child(grain_node, "first_kw") is not None,
                              anchor=anchor, pivot=pivot)
        items.append(MatchItem(expr=_build_expr_node(expr_node), grain=grain))
    return items


def _build_assign_item(node: Node) -> Assign:
    var = _child(node, "variable")
    return Assign(name=_build_variable(var), value=_build_expr(_child(node, "expr")))


def _build_ref(node: Node) -> Expr:
    return _build_expr_node(_inner(node))


def _build_order_item(node: Node) -> OrderItem:
    ref = _inner(node)
    direction = "asc"
    d = _child(node, "direction")
    if d is not None:
        direction = d.text.lower()
    return OrderItem(expr=_build_expr_node(ref), direction=direction)


# ---------------------------------------------------------------------------
# Boolean expressions
# ---------------------------------------------------------------------------

def _build_or(node: Node) -> Expr:
    terms = [_build_and(c) for c in _children(node, "and_expr")]
    if len(terms) == 1:
        return terms[0]
    return Or(tuple(terms))


def _build_and(node: Node) -> Expr:
    terms = [_build_unary(c) for c in _children(node, "unary")]
    if len(terms) == 1:
        return terms[0]
    return And(tuple(terms))


def _build_unary(node: Node) -> Expr:
    # unary = not_op unary / "(" _ or_expr ")" / condition / field_ref
    if _child(node, "not_op") is not None:
        return Not(_build_unary(_children(node, "unary")[0]))
    cond = _child(node, "condition")
    if cond is not None:
        return _build_condition(cond)
    if (or_node := _child(node, "or_expr")) is not None:
        return _build_or(or_node)
    # bare field reference: existence/non-empty check
    return _build_field_ref(_inner(_child(node, "field_ref")))


def _build_condition(node: Node) -> Comparison:
    lhs = _build_expr_node(_inner(_child(node, "lhs_expr")))
    rhs = _build_expr_node(_inner(_child(node, "rhs_expr")))
    op = _child(node, "op").text.strip().lower()
    return Comparison(
        left=lhs, op=op, right=rhs,
        nocase=_child(node, "nocase_kw") is not None,
        quantifier="any" if _child(node, "any_kw") is not None else None,
    )


# ---------------------------------------------------------------------------
# Operands
# ---------------------------------------------------------------------------

def _build_expr(node: Node) -> Expr:
    return _build_expr_node(_inner(node))


def _build_expr_node(node: Node) -> Expr:
    name = node.expr_name
    if name == "func_call":
        fname = _child(node, "func_name").text.lower()
        args = _child(node, "arg_list")
        arg_exprs = tuple(_build_expr(c) for c in _children(args, "expr")) if args else ()
        return FuncCall(name=fname, args=arg_exprs)
    if name == "or_expr":
        # A function argument may be a full boolean condition, e.g.
        # ``if(x > 1, ...)``. _build_or already collapses a single bare
        # term (no and/or) down to that term's own node.
        return _build_or(node)
    if name == "list_ref":
        idents = _children(node, "ident")
        return ListRef(table=idents[0].text,
                       column=idents[1].text if len(idents) > 1 else None)
    if name == "variable":
        return VarRef(name=_build_variable(node))
    if name == "field_ref":
        return _build_field_ref(_inner(node))
    if name == "literal":
        return _build_literal(_inner(node))
    raise UDMQueryError(f"Cannot build expression from rule {name!r}: {node.text!r}")


def _build_variable(node: Node) -> str:
    return _children(node, "ident")[0].text


def _build_field_ref(node: Node) -> FieldRef:
    """``node`` is a ``dollar_prefixed`` or ``bare_path`` node."""
    if node.expr_name == "dollar_prefixed":
        prefix = _children(node, "ident")[0].text
        inner = _build_field_ref(_child(node, "bare_path"))
        return FieldRef(segments=inner.segments, prefix=prefix)
    # bare_path
    segments: list = [_children(node, "ident")[0].text]
    for tail in _children(node, "path_tail"):
        _collect_tail(tail, segments)
    return FieldRef(segments=tuple(segments))


def _collect_tail(tail: Node, segments: list) -> None:
    for c in _named(tail):
        if c.expr_name == "ident":
            segments.append(c.text)
        elif c.expr_name == "index_or_key":
            s = _child(c, "string_lit")
            if s is not None:
                segments.append(Key(_unescape_string(s.text[1:-1])))
            else:
                segments.append(int(_digits(c)))


def _build_literal(node: Node) -> Literal:
    name = node.expr_name
    if name == "string_lit":
        return Literal(_unescape_string(node.text[1:-1]), "string")
    if name == "regex_lit":
        return Literal(node.text[1:-1].replace("\\/", "/"), "regex")
    if name == "number":
        txt = node.text
        return Literal(float(txt) if "." in txt else int(txt), "number")
    if name == "boolean":
        return Literal(node.text.lower() == "true", "boolean")
    if name == "template_var":
        return Literal(node.text[2:-1], "template")
    if name == "bareword":
        return Literal(node.text, "bare")
    raise UDMQueryError(f"Unknown literal {name!r}: {node.text!r}")


def _unescape_string(s: str) -> str:
    """Resolve the two documented UDM string escapes: ``\\\"`` and ``\\\\``."""
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s) and s[i + 1] in ('"', "\\"):
            out.append(s[i + 1])
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)
