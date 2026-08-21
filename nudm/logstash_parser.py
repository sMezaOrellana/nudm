"""PEG parser for the SecOps parser dialect: text ->
:class:`nudm.logstash_nodes.Parser` AST.

Uses :mod:`parsimonious` with the PEG grammar from
:mod:`nudm.logstash_grammar`. After building the AST, a structural
validation pass rejects unknown plugins and unknown ``mutate`` operations
up front (same spirit as the schema-aware validation the query/rule
compilers do), so a typo fails at parse time rather than mid-run.
"""
from __future__ import annotations

from parsimonious.exceptions import ParseError as ParsimoniousParseError
from parsimonious.grammar import Grammar
from parsimonious.nodes import Node

from .logstash_grammar import GRAMMAR
from .logstash_nodes import (
    And,
    ArrayLit,
    Comparison,
    CondExpr,
    FieldRef,
    ForStmt,
    IfStmt,
    Literal,
    Not,
    Or,
    Parser,
    PluginCall,
    Stmt,
)

_GRAMMAR = Grammar(GRAMMAR)


class UDMParserError(ValueError):
    """Raised when a SecOps parser can't be parsed (or uses an unknown
    plugin / mutate operation)."""


#: Plugins documented in the parser syntax reference (minus ``xml``, which
#: is recognized but rejected -- XPath support isn't implemented).
KNOWN_PLUGINS = (
    "grok", "json", "kv", "csv", "mutate", "date", "base64", "drop",
    "statedump",
)

#: ``mutate`` operations documented for the SecOps parser.
MUTATE_OPS = (
    "convert", "gsub", "lowercase", "uppercase", "merge", "rename",
    "replace", "remove_field", "copy", "split",
)


def parse_parser(text: str) -> Parser:
    """Parse a ``filter { ... }`` parser into a
    :class:`~nudm.logstash_nodes.Parser` AST."""
    try:
        tree = _GRAMMAR.parse(text)
    except ParsimoniousParseError as exc:  # noqa: TRY003
        line = text.count("\n", 0, exc.pos) + 1
        col = exc.pos - text.rfind("\n", 0, exc.pos)
        raise UDMParserError(
            f"Syntax error at line {line}, column {col}: "
            f"expected {exc.expr.name if exc.expr else '?'} near "
            f"{text[exc.pos:exc.pos + 20]!r}"
        ) from exc
    parser = _build_parser(tree)
    _validate(parser.statements)
    return parser


# ---------------------------------------------------------------------------
# Generic tree helpers (same approach as nudm.parser)
# ---------------------------------------------------------------------------

def _named(node: Node) -> list[Node]:
    """Named grammar-rule nodes reachable from ``node`` without passing
    through another named node (descends through unnamed wrappers)."""
    out: list[Node] = []
    for c in node.children:
        if c.expr_name:
            out.append(c)
        else:
            out.extend(_named(c))
    return out


def _inner(node: Node) -> Node:
    return _named(node)[0]


def _child(node: Node, name: str) -> Node | None:
    for c in _named(node):
        if c.expr_name == name:
            return c
    return None


def _children(node: Node, name: str) -> list[Node]:
    return [c for c in _named(node) if c.expr_name == name]


# ---------------------------------------------------------------------------
# Statements
# ---------------------------------------------------------------------------

def _build_parser(node: Node) -> Parser:
    block = _child(node, "filter_block")
    return Parser(statements=tuple(_build_statements(_child(block, "stmt_list"))))


def _build_statements(node: Node | None) -> list[Stmt]:
    if node is None:
        return []
    return [_build_statement(s) for s in _children(node, "statement")]


def _build_statement(node: Node) -> Stmt:
    inner = _inner(node)
    if inner.expr_name == "if_stmt":
        return _build_if(inner)
    if inner.expr_name == "for_stmt":
        return _build_for(inner)
    return _build_plugin(inner)


def _build_if(node: Node) -> IfStmt:
    # ``condition`` flattens to ``or_expr`` in the parse tree.
    cond = _build_or(_child(node, "or_expr"))
    then_body = tuple(_build_statements(_child(node, "stmt_list")))
    else_body: tuple[Stmt, ...] | None = None
    else_node = _child(node, "else_clause")
    if else_node is not None:
        nested_if = _child(else_node, "if_stmt")
        if nested_if is not None:
            else_body = (_build_if(nested_if),)
        else:
            else_body = tuple(_build_statements(
                _child(_child(else_node, "else_block"), "stmt_list")))
    return IfStmt(cond=cond, then_body=then_body, else_body=else_body)


def _build_for(node: Node) -> ForStmt:
    loop_vars = tuple(i.text for i in _children(_child(node, "for_vars"), "ident"))
    iter_node = _child(node, "for_iter")
    if _child(iter_node, "xml_iter") is not None:
        raise UDMParserError(
            "for ... in xml(...) loops are not supported (xml plugin is not "
            "implemented)"
        )
    iterable = _children(iter_node, "ident")[0].text
    return ForStmt(
        loop_vars=loop_vars,
        iterable=iterable,
        is_map=_child(node, "map_kw") is not None,
        body=tuple(_build_statements(_child(node, "stmt_list"))),
    )


def _build_plugin(node: Node) -> PluginCall:
    name = _children(node, "ident")[0].text
    args: dict[str, object] = {}
    for pair in _children(node, "arg_pair"):
        # ``arg_name`` flattens to ``ident`` in the parse tree; ``value`` is
        # its own named node so it isn't descended into, leaving the argument
        # name as the only direct ``ident`` child.
        key = _children(pair, "ident")[0].text
        args[key] = _build_value(_child(pair, "value"))
    return PluginCall(name=name, args=args)


# ---------------------------------------------------------------------------
# Values
# ---------------------------------------------------------------------------

def _build_value(node: Node) -> object:
    inner = _inner(node)
    name = inner.expr_name
    if name == "array":
        items = _child(inner, "array_items")
        if items is None:
            return []
        return [_build_value(v) for v in _children(items, "value")]
    if name == "hash":
        out: dict[object, object] = {}
        for pair in _children(inner, "hash_pair"):
            key_node = _inner(_child(pair, "hash_key"))
            key = (_unescape(key_node.text[1:-1], key_node.text[0])
                   if key_node.expr_name == "string" else key_node.text)
            out[key] = _build_value(_child(pair, "value"))
        return out
    if name == "string":
        return _unescape(inner.text[1:-1], inner.text[0])
    if name == "boolean":
        return inner.text == "true"
    if name == "number":
        return float(inner.text) if "." in inner.text else int(inner.text)
    if name == "bareword":
        return inner.text
    raise UDMParserError(f"Unknown value {name!r}: {inner.text!r}")


def _unescape(body: str, quote: str) -> str:
    """Resolve the documented escapes: ``\\<quote>`` and ``\\\\``. Anything
    else is left as-is, which is what implements the docs' double-backslash
    rule for regexes (``"\\\\s"`` parses to ``\\s`` for the regex engine)."""
    out = []
    i = 0
    while i < len(body):
        if body[i] == "\\" and i + 1 < len(body) and body[i + 1] in (quote, "\\"):
            out.append(body[i + 1])
            i += 2
        else:
            out.append(body[i])
            i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# Conditionals
# ---------------------------------------------------------------------------

def _build_or(node: Node) -> CondExpr:
    terms = [_build_and(c) for c in _children(node, "and_expr")]
    return terms[0] if len(terms) == 1 else Or(tuple(terms))


def _build_and(node: Node) -> CondExpr:
    terms = [_build_not(c) for c in _children(node, "not_expr")]
    return terms[0] if len(terms) == 1 else And(tuple(terms))


def _build_not(node: Node) -> CondExpr:
    # not_expr = bang not_expr / "(" condition ")" / comparison / field_ref
    # ``condition`` flattens to ``or_expr`` in the parse tree.
    if _child(node, "bang") is not None:
        return Not(_build_not(_children(node, "not_expr")[0]))
    if (paren := _child(node, "or_expr")) is not None:
        return _build_or(paren)
    if (cmp := _child(node, "comparison")) is not None:
        return _build_comparison(cmp)
    return _build_field_ref(_child(node, "field_ref"))


def _build_comparison(node: Node) -> Comparison:
    left, right = (_build_operand(o) for o in _children(node, "operand"))
    op = _child(node, "cmp_op").text.strip().lower()
    return Comparison(left=left, op=op, right=right)


def _build_operand(node: Node) -> CondExpr:
    inner = _inner(node)
    if inner.expr_name == "field_ref":
        return _build_field_ref(inner)
    if inner.expr_name == "array":
        return ArrayLit(tuple(_build_value(v)
                              for v in _children(_child(inner, "array_items") or inner, "value")))
    if inner.expr_name == "string":
        return Literal(_unescape(inner.text[1:-1], inner.text[0]))
    if inner.expr_name == "boolean":
        return Literal(inner.text == "true")
    if inner.expr_name == "number":
        return Literal(float(inner.text) if "." in inner.text else int(inner.text))
    raise UDMParserError(f"Unknown operand {inner.expr_name!r}: {inner.text!r}")


def _build_field_ref(node: Node) -> FieldRef:
    segments: list[str] = []
    for key in _children(node, "field_key"):
        inner = _inner(key)
        if inner.expr_name == "string":
            segments.append(_unescape(inner.text[1:-1], inner.text[0]))
        else:
            segments.append(inner.text)
    return FieldRef(segments=tuple(segments))


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _validate(stmts: tuple[Stmt, ...]) -> None:
    for stmt in stmts:
        if isinstance(stmt, PluginCall):
            if stmt.name == "xml":
                raise UDMParserError(
                    "the xml plugin is not supported (no XPath support yet)"
                )
            if stmt.name not in KNOWN_PLUGINS:
                raise UDMParserError(f"unknown filter plugin {stmt.name!r}")
            if stmt.name == "mutate":
                for op in stmt.args:
                    if op != "on_error" and op not in MUTATE_OPS:
                        raise UDMParserError(f"unknown mutate operation {op!r}")
        elif isinstance(stmt, IfStmt):
            _validate(stmt.then_body)
            if stmt.else_body:
                _validate(stmt.else_body)
        elif isinstance(stmt, ForStmt):
            _validate(stmt.body)
