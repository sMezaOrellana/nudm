"""Compile a :class:`nudm.nodes.Query` AST into a DuckDB SQL statement.

Design (see conversation / project notes for the full rationale):

* The data source is a DuckDB relation with a single ``event`` column of
  type ``JSON``, one row per UDM event, holding the *exact* JSON shape the
  real Google SecOps API returns (camelCase keys are NOT assumed here --
  see :mod:`nudm.fake_data`, which loads fake events keyed by the same
  snake_case canonical paths the query language itself uses, so field refs
  translate to JSON paths with zero case conversion).
* Every field access is compiled as a chain of ``json_extract`` calls
  rather than a single batched JSON path string. This is slightly more
  verbose SQL but sidesteps JSON-path escaping edge cases entirely, and
  lets a ``repeated`` (array) segment be intercepted mid-walk and turned
  into an ``EXISTS (... json_each ...)`` predicate -- UDM's implicit
  "any element matches" semantics for repeated fields.
* ``json_extract`` returns a JSON-typed (quoted) value, not a native SQL
  scalar, so every value that came from a JSON path has to be unwrapped
  with ``json_extract_string`` before it's cast to a comparable type; a
  plain SQL literal (from a ``Literal``/param) is already native-typed and
  must *not* be run through that unwrap. ``_typed()`` is the single place
  that applies the right one based on an explicit ``is_json`` flag carried
  alongside every compiled scalar.
* ``$e`` / ``$x.`` event-variable prefixes are ignored: this compiler
  supports a single implicit event stream, not multi-variable joins
  across ``events:`` blocks. Scalar YARA-L functions (``timestamp.get_date``
  etc.) are not implemented -- using one in a condition raises
  :class:`UDMCompileError` naming the function rather than silently
  producing wrong SQL. Template variables (``${x}``) are resolved from an
  explicit ``params`` dict at compile time.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from .nodes import (
    And,
    Comparison,
    Expr,
    FieldRef,
    FuncCall,
    Key,
    ListRef,
    Literal,
    Not,
    Or,
    Query,
    VarRef,
)
from .schema import DUCKDB_SCALAR_TYPES, GROUPED_FIELDS, FieldInfo, UDMSchema

# ---------------------------------------------------------------------------
# Aggregate function names (outcome section) -> DuckDB equivalents.
# ---------------------------------------------------------------------------

_AGGREGATES = {
    "count": "count",
    "count_distinct": "count(distinct {0})",
    "sum": "sum",
    "avg": "avg",
    "min": "min",
    "max": "max",
    "stddev": "stddev_samp",
    "array": "list",
    "array_distinct": "list(distinct {0})",
    # Best-effort: YARA-L earliest()/latest() return the value observed at
    # the min/max event timestamp; here we simplify to min()/max() of the
    # argument itself, which is only correct when the argument *is* a
    # timestamp. Good enough for a test-data mock; documented limitation.
    "earliest": "min",
    "latest": "max",
}


class UDMCompileError(ValueError):
    """Raised when a parsed query can't be compiled to SQL."""


@dataclass
class CompileContext:
    schema: UDMSchema
    params: dict[str, str] = field(default_factory=dict)
    events: dict[str, Expr] = field(default_factory=dict)  # $var -> Expr, from events-section assigns


# A leaf callback receives the fully-resolved, still-JSON-typed value
# expression and its schema FieldInfo (or None), and returns a SQL
# predicate string.
Leaf = Callable[[str, Optional[FieldInfo]], str]


# ---------------------------------------------------------------------------
# Field-path -> SQL
# ---------------------------------------------------------------------------

def _step_str(sql: str, name: str) -> str:
    escaped = name.replace("\\", "\\\\").replace('"', '\\"')
    return f"json_extract({sql}, '$.\"{escaped}\"')"


def _step_int(sql: str, idx: int) -> str:
    return f"json_extract({sql}, '$[{idx}]')"


def _compile_predicate(
    segments: tuple, schema: UDMSchema, base: str, leaf: Leaf,
    path_prefix: tuple[str, ...] = (),
) -> str:
    """Walk a FieldRef's segments starting at ``base`` (a SQL expression
    yielding a JSON value). Applies ``leaf(value_sql, field_info)`` once the
    path bottoms out, except that a ``repeated`` segment not immediately
    followed by an explicit index turns the *rest* of the walk into an
    ``EXISTS`` predicate over each array element (UDM's implicit
    any-element-matches semantics for repeated fields).

    Every plain path segment is validated against ``schema`` as it's
    consumed (every prefix of a real UDM field path is itself a schema
    entry, so this catches a typo'd/nonexistent field as soon as the walk
    diverges from the schema) -- except once a dynamic map/struct key has
    been crossed, since schema lookup can't see past that point.
    ``path_prefix`` seeds ``path_parts`` when recursing into a repeated
    field's element type, so validation keeps using full dotted paths."""
    sql = base
    path_parts: list[str] = list(path_prefix)
    known = True
    i = 0
    n = len(segments)
    while i < n:
        seg = segments[i]
        if isinstance(seg, int):
            sql = _step_int(sql, seg)
            i += 1
            continue
        if isinstance(seg, Key):
            parent_info = schema.lookup(".".join(path_parts))
            if parent_info and parent_info.repeated:
                # Label-like repeated {key, value, ...} list: scalar lookup.
                key_lit = seg.value.replace("'", "''")
                sql = (
                    f"(SELECT json_extract(t.value, '$.\"value\"') FROM json_each({sql}) AS t "
                    f"WHERE json_extract_string(t.value, '$.\"key\"') = '{key_lit}' LIMIT 1)"
                )
            else:
                # google.protobuf.Struct-style map field.
                sql = _step_str(sql, seg.value)
            path_parts = []  # schema lookup can't see past a dynamic key
            known = False
            i += 1
            continue
        # The ``.fields[...]`` UDM DSL idiom (e.g. ``additional.fields["x"]``):
        # "fields" is a fixed syntax token for indexing into a
        # google.protobuf.Struct field, not a real JSON nesting level, so it
        # must be skipped rather than looked up.
        prev_info = schema.lookup(".".join(path_parts)) if path_parts else None
        if (
            seg == "fields" and prev_info is not None
            and prev_info.type == "google.protobuf.Struct"
            and i + 1 < n and isinstance(segments[i + 1], Key)
        ):
            i += 1
            continue
        # plain path segment
        path_parts.append(seg)
        cur_path = ".".join(path_parts)
        info = schema.lookup(cur_path)
        if known and info is None and cur_path != "graph":
            raise UDMCompileError(f"Unknown UDM field: {cur_path!r}")
        if info and info.repeated:
            if i + 1 < n and isinstance(segments[i + 1], int):
                sql = _step_str(sql, seg)
                sql = _step_int(sql, segments[i + 1])
                i += 2
                continue
            if i + 1 < n and isinstance(segments[i + 1], Key):
                # Label-like repeated {key, value, ...} list: scalar lookup,
                # not a per-element EXISTS predicate.
                array_sql = _step_str(sql, seg)
                key_lit = segments[i + 1].value.replace("'", "''")
                sql = (
                    f"(SELECT json_extract(t.value, '$.\"value\"') FROM json_each({array_sql}) AS t "
                    f"WHERE json_extract_string(t.value, '$.\"key\"') = '{key_lit}' LIMIT 1)"
                )
                path_parts = []
                known = False
                i += 2
                continue
            array_sql = _step_str(sql, seg)
            remainder = segments[i + 1:]
            inner = (
                _compile_predicate(remainder, schema, "t.value", leaf, path_prefix=tuple(path_parts))
                if remainder else leaf("t.value", info)
            )
            return f"EXISTS (SELECT 1 FROM json_each({array_sql}) AS t WHERE {inner})"
        sql = _step_str(sql, seg)
        i += 1
    final_info = schema.lookup(".".join(path_parts)) if path_parts else None
    return leaf(sql, final_info)


def _resolve_grouped(fr: FieldRef) -> tuple[str, ...] | None:
    """If ``fr`` is a bare grouped-field name (e.g. ``ip``), return the
    concrete UDM paths it expands to."""
    if len(fr.segments) == 1 and isinstance(fr.segments[0], str):
        return GROUPED_FIELDS.get(fr.segments[0])
    return None


def _path_to_segments(path: str) -> tuple:
    return tuple(path.split("."))


def _field_predicate(fr: FieldRef, ctx: CompileContext, leaf: Leaf, base: str = "event") -> str:
    grouped = _resolve_grouped(fr)
    if grouped is not None:
        parts = [_compile_predicate(_path_to_segments(p), ctx.schema, base, leaf) for p in grouped]
        return "(" + " OR ".join(parts) + ")"
    return _compile_predicate(fr.segments, ctx.schema, base, leaf)


def _existence_leaf(value_sql: str, info: Optional[FieldInfo]) -> str:
    text = f"json_extract_string({value_sql}, '$')"
    return f"({text} IS NOT NULL AND {text} != '')"


# ---------------------------------------------------------------------------
# Literals, typing, and plain (non-repeated-aware) scalar expressions
# ---------------------------------------------------------------------------

def _sql_str(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _literal_sql(lit: Literal, ctx: CompileContext) -> str:
    if lit.kind in ("string", "bare"):
        return _sql_str(str(lit.value))
    if lit.kind == "number":
        return repr(lit.value)
    if lit.kind == "boolean":
        return "TRUE" if lit.value else "FALSE"
    if lit.kind == "template":
        if lit.value not in ctx.params:
            raise UDMCompileError(f"No value supplied for template variable ${{{lit.value}}}")
        return _sql_str(ctx.params[lit.value])
    if lit.kind == "regex":
        raise UDMCompileError("Regex literals must be compared with = or != against a field")
    raise UDMCompileError(f"Unknown literal kind {lit.kind!r}")


def _plain_scalar(expr: Expr, ctx: CompileContext, base: str = "event") -> tuple[str, Optional[FieldInfo], bool]:
    """Compile an expression to a plain SQL scalar (no repeated-field
    EXISTS-wrapping). Used for the side of a comparison that isn't the
    "driving" FieldRef. Returns ``(sql, info, is_json)``."""
    if isinstance(expr, Literal):
        return _literal_sql(expr, ctx), None, False
    if isinstance(expr, VarRef):
        if expr.name not in ctx.events:
            raise UDMCompileError(f"Undefined placeholder variable ${expr.name}")
        return _plain_scalar(ctx.events[expr.name], ctx, base)
    if isinstance(expr, FieldRef):
        holder: dict[str, object] = {}

        def leaf(value_sql: str, info: Optional[FieldInfo]) -> str:
            holder["info"] = info
            holder["sql"] = value_sql
            return value_sql

        sql = _field_predicate(expr, ctx, leaf, base)
        return sql, holder.get("info"), True
    if isinstance(expr, FuncCall):
        raise UDMCompileError(f"Scalar function {expr.name!r} is not supported in conditions")
    raise UDMCompileError(f"Cannot compile {type(expr).__name__} as a scalar expression")


def _duck_type(info: Optional[FieldInfo]) -> str:
    if info is None or info.enum:
        return "VARCHAR"
    return DUCKDB_SCALAR_TYPES.get(info.type, "VARCHAR")


def _typed(sql: str, info: Optional[FieldInfo], is_json: bool) -> str:
    """A value as a native, correctly-typed SQL scalar: unwrapped from JSON
    (if it came from one) and cast to the field's DuckDB type."""
    text = f"json_extract_string({sql}, '$')" if is_json else sql
    return f"CAST({text} AS {_duck_type(info)})"


def _text(sql: str, is_json: bool) -> str:
    """A value as plain SQL text, no type cast (for LOWER()/regex use)."""
    return f"json_extract_string({sql}, '$')" if is_json else f"CAST({sql} AS VARCHAR)"


# ---------------------------------------------------------------------------
# Comparisons
# ---------------------------------------------------------------------------

_OPS = {"=": "=", "!=": "!=", "<": "<", ">": ">", "<=": "<=", ">=": ">="}


def _check_enum_literal(info: Optional[FieldInfo], lit: Expr, schema: UDMSchema) -> None:
    """Raise if ``lit`` is a string/bare literal compared against an
    enum-typed field but isn't one of that enum's real member names. The
    ``field = ""`` / ``field != ""`` existence-check idiom is exempted: an
    empty string there isn't claiming to be an enum value."""
    if (
        info is None or not info.enum
        or not isinstance(lit, Literal) or lit.kind not in ("string", "bare")
        or lit.value == ""
    ):
        return
    values = schema.enum_values(info.type)
    if values is not None and lit.value not in values:
        raise UDMCompileError(
            f"{lit.value!r} is not a valid value for enum {info.type} (field {info.path!r})"
        )


def _compile_comparison(cmp: Comparison, ctx: CompileContext) -> str:
    left_is_field = isinstance(cmp.left, FieldRef)
    right_is_field = isinstance(cmp.right, FieldRef)

    if cmp.op == "in":
        if not isinstance(cmp.right, ListRef):
            raise UDMCompileError("'in' requires a %reference_list.column on the right-hand side")
        if not left_is_field:
            raise UDMCompileError("'in' requires a field reference on the left-hand side")
        table = _sql_str(cmp.right.table)
        column = _sql_str(cmp.right.column) if cmp.right.column else "NULL"

        def leaf(value_sql: str, info: Optional[FieldInfo]) -> str:
            casted = _typed(value_sql, info, True)
            return (
                f"EXISTS (SELECT 1 FROM reference_lists "
                f"WHERE list_name = {table} AND column_name = {column} "
                f"AND value = CAST({casted} AS VARCHAR))"
            )

        return _field_predicate(cmp.left, ctx, leaf)

    if isinstance(cmp.right, Literal) and cmp.right.kind == "regex":
        if not left_is_field:
            raise UDMCompileError("A regex comparison requires a field reference on the left-hand side")
        pattern = cmp.right.value.replace("'", "''")
        flags = "(?i)" if cmp.nocase else ""

        def leaf(value_sql: str, info: Optional[FieldInfo]) -> str:
            pred = f"regexp_matches({_text(value_sql, True)}, '{flags}{pattern}')"
            return f"NOT {pred}" if cmp.op == "!=" else pred

        return _field_predicate(cmp.left, ctx, leaf)

    if isinstance(cmp.left, Literal) and cmp.left.kind == "regex":
        if not right_is_field:
            raise UDMCompileError("A regex comparison requires a field reference")
        pattern = cmp.left.value.replace("'", "''")
        flags = "(?i)" if cmp.nocase else ""

        def leaf(value_sql: str, info: Optional[FieldInfo]) -> str:
            pred = f"regexp_matches({_text(value_sql, True)}, '{flags}{pattern}')"
            return f"NOT {pred}" if cmp.op == "!=" else pred

        return _field_predicate(cmp.right, ctx, leaf)

    op = _OPS[cmp.op]

    if left_is_field:
        other_sql, other_info, other_json = _plain_scalar(cmp.right, ctx)

        def leaf(value_sql: str, info: Optional[FieldInfo]) -> str:
            _check_enum_literal(info, cmp.right, ctx.schema)
            if cmp.nocase:
                return f"LOWER({_text(value_sql, True)}) {op} LOWER({_text(other_sql, other_json)})"
            return f"{_typed(value_sql, info, True)} {op} {_typed(other_sql, info or other_info, other_json)}"

        return _field_predicate(cmp.left, ctx, leaf)

    if right_is_field:
        other_sql, other_info, other_json = _plain_scalar(cmp.left, ctx)

        def leaf(value_sql: str, info: Optional[FieldInfo]) -> str:
            _check_enum_literal(info, cmp.left, ctx.schema)
            if cmp.nocase:
                return f"LOWER({_text(other_sql, other_json)}) {op} LOWER({_text(value_sql, True)})"
            return f"{_typed(other_sql, info or other_info, other_json)} {op} {_typed(value_sql, info, True)}"

        return _field_predicate(cmp.right, ctx, leaf)

    left_sql, left_info, left_json = _plain_scalar(cmp.left, ctx)
    right_sql, right_info, right_json = _plain_scalar(cmp.right, ctx)
    if cmp.nocase:
        return f"LOWER({_text(left_sql, left_json)}) {op} LOWER({_text(right_sql, right_json)})"
    info = left_info or right_info
    return f"{_typed(left_sql, info, left_json)} {op} {_typed(right_sql, info, right_json)}"


# ---------------------------------------------------------------------------
# Boolean expressions
# ---------------------------------------------------------------------------

def _compile_bool(expr: Expr, ctx: CompileContext) -> str:
    if isinstance(expr, And):
        return "(" + " AND ".join(_compile_bool(c, ctx) for c in expr.children) + ")"
    if isinstance(expr, Or):
        return "(" + " OR ".join(_compile_bool(c, ctx) for c in expr.children) + ")"
    if isinstance(expr, Not):
        return f"NOT ({_compile_bool(expr.child, ctx)})"
    if isinstance(expr, Comparison):
        return _compile_comparison(expr, ctx)
    if isinstance(expr, FieldRef):
        return _field_predicate(expr, ctx, _existence_leaf)
    raise UDMCompileError(f"Cannot compile {type(expr).__name__} as a boolean expression")


# ---------------------------------------------------------------------------
# match / outcome / dedup / order / limit
# ---------------------------------------------------------------------------

def _field_alias(fr: FieldRef) -> str:
    return "_".join(str(s.value) if isinstance(s, Key) else str(s) for s in fr.segments)


def _compile_ref_item(expr: Expr, ctx: CompileContext) -> tuple[str, str]:
    """Compile a VarRef/FieldRef used in match/dedup/order to (sql, alias)."""
    if isinstance(expr, VarRef):
        if expr.name not in ctx.events:
            raise UDMCompileError(f"Undefined placeholder variable ${expr.name}")
        sql, info, is_json = _plain_scalar(ctx.events[expr.name], ctx)
        return _typed(sql, info, is_json), expr.name
    if isinstance(expr, FieldRef):
        sql, info, is_json = _plain_scalar(expr, ctx)
        return _typed(sql, info, is_json), _field_alias(expr)
    raise UDMCompileError(f"Cannot use {type(expr).__name__} here")


def _compile_outcome_value(expr: Expr, ctx: CompileContext) -> str:
    if isinstance(expr, FuncCall):
        template = _AGGREGATES.get(expr.name)
        if template is None:
            raise UDMCompileError(f"Unsupported outcome function {expr.name!r}")
        if len(expr.args) != 1:
            raise UDMCompileError(f"{expr.name}() expects exactly one argument")
        arg_sql, arg_info, arg_json = _plain_scalar(expr.args[0], ctx)
        arg_casted = _typed(arg_sql, arg_info, arg_json)
        return template.format(arg_casted) if "{0}" in template else f"{template}({arg_casted})"
    sql, info, is_json = _plain_scalar(expr, ctx)
    return _typed(sql, info, is_json)


def _order_and_limit_sql(query: Query, ctx: CompileContext, alias_scope: set[str]) -> str:
    out = ""
    if query.order:
        terms = []
        for item in query.order:
            if isinstance(item.expr, VarRef) and item.expr.name in alias_scope:
                ref = f'"{item.expr.name}"'
            elif isinstance(item.expr, FieldRef) and _field_alias(item.expr) in alias_scope:
                ref = f'"{_field_alias(item.expr)}"'
            else:
                ref, _alias = _compile_ref_item(item.expr, ctx)
            terms.append(f"{ref} {item.direction.upper()}")
        out += " ORDER BY " + ", ".join(terms)
    if query.limit is not None:
        out += f" LIMIT {query.limit}"
    return out


def compile_query(query: Query, schema: UDMSchema, params: Optional[dict[str, str]] = None) -> str:
    """Compile a parsed :class:`Query` to a DuckDB SQL statement, assuming a
    relation named ``events`` with a single ``JSON``-typed ``event`` column,
    and (for the ``in`` operator) a ``reference_lists(list_name, column_name,
    value)`` relation."""
    ctx = CompileContext(schema=schema, params=params or {}, events=dict(query.assignments))
    where_sql = _compile_bool(query.where, ctx) if query.where is not None else None

    if query.match or query.outcome:
        select_parts: list[str] = []
        group_aliases: list[str] = []
        alias_scope: set[str] = set()
        for item in query.match:
            sql, alias = _compile_ref_item(item.expr, ctx)
            select_parts.append(f'{sql} AS "{alias}"')
            group_aliases.append(f'"{alias}"')
            alias_scope.add(alias)
        for assign in query.outcome:
            val_sql = _compile_outcome_value(assign.value, ctx)
            select_parts.append(f'{val_sql} AS "{assign.name}"')
            alias_scope.add(assign.name)
        sql = f"SELECT {', '.join(select_parts)} FROM events"
        if where_sql:
            sql += f" WHERE {where_sql}"
        if group_aliases:
            sql += " GROUP BY " + ", ".join(group_aliases)
        sql += _order_and_limit_sql(query, ctx, alias_scope)
        return sql

    prefix = "SELECT"
    if query.dedup:
        dedup_cols = [_compile_ref_item(d, ctx)[0] for d in query.dedup]
        prefix = "SELECT DISTINCT ON (" + ", ".join(dedup_cols) + ")"
    sql = f"{prefix} name, event FROM events"
    if where_sql:
        sql += f" WHERE {where_sql}"
    sql += _order_and_limit_sql(query, ctx, set())
    return sql
