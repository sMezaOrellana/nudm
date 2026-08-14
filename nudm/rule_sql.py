"""Compile a :class:`nudm.rule_nodes.Rule` AST into a DuckDB SQL statement.

Architecturally distinct from :mod:`nudm.duckdb_sql` (which assumes one
implicit event stream): a rule's defining feature is multi-event
correlation, so this module partitions ``events:`` by event variable
(``$e1``, ``$e2``, ...), compiles each into its own filtered CTE, and
joins them on shared placeholder values. It reuses duckdb_sql's field-path
walking / typing / literal / aggregate machinery directly (those functions
already take a ``base`` SQL expression parameter) rather than
reimplementing field compilation.

Design simplifications, called out explicitly (see the approved plan):

* Every non-anchor event variable is joined with ``LEFT JOIN``, uniformly.
  ``condition:``'s ``$var``/``#var``/``!$var`` are compiled as ordinary
  ``HAVING``-clause aggregate checks (``count(alias.event) > 0`` and its
  negation) against the joined-but-possibly-null rows, rather than trying
  to pick INNER vs LEFT per variable up front -- this sidesteps a whole
  class of special-casing at the cost of an always-present LEFT JOIN.
* A plain ``over N<unit>`` window is a real *tumbling* window (rows bucketed
  by ``floor(epoch(ts) / window_seconds)``, bucket equality added to every
  join predicate, bucket included in ``GROUP BY``) -- not a continuous
  sliding window. Two events 1 second apart but straddling a bucket
  boundary won't correlate; a fully continuous sliding-window join is a
  materially larger algorithm (event-stream clustering, not a fixed join).
* A ``before``/``after $pivot`` window requires the pivot to be the first
  event variable declared in ``events:`` (kept general enough to cover the
  documented pattern without an N-way pivot graph).
* ``graph.*`` fields and ``options: suppression_window`` are rejected with
  a clear error (excluded from this pass; see the module docstring in
  :mod:`nudm.rule_nodes`).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .duckdb_sql import (
    UDMCompileError,
    CompileContext,
    _AGGREGATES,
    _compile_bool,
    _literal_sql,
    _compile_predicate,
    _plain_scalar,
    _typed,
)
from .nodes import And, Assign, Comparison, Expr, FieldRef, FuncCall, Key, Literal, Not, Or, VarRef
from .rule_nodes import EventCount, EventRef, Rule
from .schema import UDMSchema

_UNIT_SECONDS = {
    "minute": 60, "hour": 3600, "day": 86400, "week": 604800,
    "month": 2592000,  # approximate (30d); documented limitation, like earliest()/latest() in duckdb_sql.py
}

_CMP_OPS = {"=": "=", "!=": "!=", "<": "<", ">": ">", "<=": "<=", ">=": ">="}


def _alias(name: str) -> str:
    return f'"{name}"'


# ---------------------------------------------------------------------------
# events: partitioning -- filters per event-variable, placeholder occurrences
# ---------------------------------------------------------------------------

def _fieldref_prefixes(expr: Expr, out: set) -> None:
    if isinstance(expr, FieldRef):
        out.add(expr.prefix)
    elif isinstance(expr, (And, Or)):
        for c in expr.children:
            _fieldref_prefixes(c, out)
    elif isinstance(expr, Not):
        _fieldref_prefixes(expr.child, out)
    elif isinstance(expr, Comparison):
        _fieldref_prefixes(expr.left, out)
        _fieldref_prefixes(expr.right, out)
    elif isinstance(expr, FuncCall):
        for a in expr.args:
            _fieldref_prefixes(a, out)


def _as_placeholder_def(expr: Expr) -> Optional[tuple[str, str, tuple]]:
    """If ``expr`` defines a placeholder -- either ``$ph = $evar.path``
    (an :class:`Assign`) or the ``$evar.path = $ph`` comparison idiom --
    return ``(placeholder_name, event_var, field_segments)``."""
    if isinstance(expr, Assign) and isinstance(expr.value, FieldRef) and expr.value.prefix:
        return expr.name, expr.value.prefix, expr.value.segments
    if isinstance(expr, Comparison) and expr.op == "=":
        l, r = expr.left, expr.right
        if isinstance(l, FieldRef) and l.prefix and isinstance(r, VarRef):
            return r.name, l.prefix, l.segments
        if isinstance(r, FieldRef) and r.prefix and isinstance(l, VarRef):
            return l.name, r.prefix, r.segments
    return None


@dataclass
class _EventPartition:
    evar_order: list           # event-variable names, first-appearance order
    filters: dict               # evar -> list[Expr] (ANDed row filters)
    placeholders: dict          # placeholder name -> list[(evar, segments)]


def _partition_events(rule: Rule) -> _EventPartition:
    filters: dict = {}
    placeholders: dict = {}
    evar_order: list = []
    deferred_global: list = []

    def touch(evar: str) -> None:
        if evar not in filters:
            filters[evar] = []
            evar_order.append(evar)

    for e in rule.events:
        ph = _as_placeholder_def(e)
        if ph is not None:
            name, evar, segs = ph
            touch(evar)
            placeholders.setdefault(name, []).append((evar, segs))
            continue
        prefixes: set = set()
        _fieldref_prefixes(e, prefixes)
        prefixes.discard(None)
        if len(prefixes) > 1:
            raise UDMCompileError(
                f"events: condition references more than one event variable "
                f"directly ({', '.join('$' + p for p in sorted(prefixes))}); "
                f"correlate them with a shared placeholder instead: {e!r}"
            )
        if len(prefixes) == 1:
            evar = next(iter(prefixes))
            touch(evar)
            filters[evar].append(e)
        else:
            deferred_global.append(e)

    if deferred_global:
        if len(evar_order) != 1:
            raise UDMCompileError(
                "events: has a condition with no $var. prefix (e.g. "
                '"metadata.event_type = ..." instead of "$e.metadata.event_type = ..."), '
                "which is ambiguous in a rule with more than one event variable"
            )
        filters[evar_order[0]].extend(deferred_global)

    if not evar_order:
        raise UDMCompileError("events: section defines no event variables")
    return _EventPartition(evar_order=evar_order, filters=filters, placeholders=placeholders)


def _check_no_graph_fields(rule: Rule) -> None:
    def walk(expr: Expr) -> None:
        if isinstance(expr, FieldRef):
            if expr.segments and expr.segments[0] == "graph":
                raise UDMCompileError("graph/entity fields are not supported in rules yet")
        elif isinstance(expr, (And, Or)):
            for c in expr.children:
                walk(c)
        elif isinstance(expr, Not):
            walk(expr.child)
        elif isinstance(expr, Comparison):
            walk(expr.left)
            walk(expr.right)
        elif isinstance(expr, FuncCall):
            for a in expr.args:
                walk(a)
        elif isinstance(expr, Assign):
            walk(expr.value)

    for e in rule.events:
        walk(e)
    for a in rule.outcome:
        walk(a.value)


# ---------------------------------------------------------------------------
# condition: event-variable polarity (is it ever referenced only negated?)
# ---------------------------------------------------------------------------

def _condition_evar_polarity(expr: Expr, negated: bool, out: dict) -> None:
    if isinstance(expr, EventRef):
        out.setdefault(expr.name, set()).add(not negated)
    elif isinstance(expr, EventCount):
        out.setdefault(expr.name, set()).add(not negated)
    elif isinstance(expr, Not):
        _condition_evar_polarity(expr.child, not negated, out)
    elif isinstance(expr, (And, Or)):
        for c in expr.children:
            _condition_evar_polarity(c, negated, out)
    elif isinstance(expr, Comparison):
        for side in (expr.left, expr.right):
            if isinstance(side, EventCount):
                out.setdefault(side.name, set()).add(not negated)


# ---------------------------------------------------------------------------
# Per-event-variable CTE
# ---------------------------------------------------------------------------

def _where_sql(filters: list, ctx: CompileContext) -> Optional[str]:
    if not filters:
        return None
    combined = filters[0] if len(filters) == 1 else And(tuple(filters))
    return _compile_bool(combined, ctx)


def _typed_leaf(value_sql: str, info) -> str:
    return _typed(value_sql, info, True)


def _ts_expr_sql(schema: UDMSchema) -> str:
    return _compile_predicate(("metadata", "event_timestamp"), schema, "event", _typed_leaf)


def _cte_sql(
    evar: str, filters: list, own_placeholders: list, needs_bucket: bool,
    window_seconds: Optional[int], schema: UDMSchema, ctx: CompileContext,
) -> tuple[str, Optional[str]]:
    where_sql = _where_sql(filters, ctx)

    select_parts = ["event"]
    seen = set()
    for name, segs in own_placeholders:
        if name in seen:
            continue
        seen.add(name)
        sql = _compile_predicate(segs, schema, "event", _typed_leaf)
        select_parts.append(f'{sql} AS {_alias("ph_" + name)}')

    ts_sql = _ts_expr_sql(schema)
    select_parts.append(f'{ts_sql} AS {_alias("_ts")}')
    if needs_bucket:
        select_parts.append(
            f'CAST(epoch({ts_sql}) / {window_seconds} AS BIGINT) AS {_alias("_bucket")}'
        )

    sql = f"SELECT {', '.join(select_parts)} FROM events"
    if where_sql:
        sql += f" WHERE {where_sql}"
    return sql, where_sql


# ---------------------------------------------------------------------------
# Join graph
# ---------------------------------------------------------------------------

def _build_joins(part: _EventPartition, anchor_of: dict, polarity: dict):
    """Returns ``(from_evar, joins, not_exists_evars)``, where ``joins`` is
    a list of ``(evar, [predicate_sql, ...])`` in the order they should be
    LEFT JOINed onto ``from_evar``, and ``not_exists_evars`` lists event
    variables with no shared placeholder that are purely negated in
    condition: (compiled as a standalone ``NOT EXISTS`` gate instead)."""
    evar_order = part.evar_order
    from_evar = evar_order[0]
    joined = {from_evar}
    joins = []
    not_exists_evars = []

    for evar in evar_order[1:]:
        preds = []
        for name, occs in part.placeholders.items():
            mine = next((s for (e, s) in occs if e == evar), None)
            if mine is None:
                continue
            anchor = anchor_of[name]
            if anchor == evar or anchor not in joined:
                continue
            preds.append(f'{_alias(evar)}.{_alias("ph_" + name)} = {_alias(anchor)}.{_alias("ph_" + name)}')
        if not preds:
            if polarity.get(evar) == {False}:
                not_exists_evars.append(evar)
                continue
            raise UDMCompileError(
                f"event variable ${evar} shares no placeholder with any "
                f"other event variable, so it can't be correlated"
            )
        joins.append((evar, preds))
        joined.add(evar)
    return from_evar, joins, not_exists_evars


def _pivot_predicate(evar: str, pivot: tuple) -> str:
    direction, pivot_evar, qty, unit = pivot
    interval = f"INTERVAL '{qty} {unit}'"
    p = f'{_alias(pivot_evar)}.{_alias("_ts")}'
    o = f'{_alias(evar)}.{_alias("_ts")}'
    if direction == "after":
        return f"{o} BETWEEN {p} AND {p} + {interval}"
    return f"{o} BETWEEN {p} - {interval} AND {p}"


# ---------------------------------------------------------------------------
# match: column resolution
# ---------------------------------------------------------------------------

def _match_column(item, part: _EventPartition, anchor_of: dict, ctx: CompileContext) -> tuple[str, str]:
    expr = item.expr
    if isinstance(expr, VarRef):
        name = expr.name
        if name not in anchor_of:
            raise UDMCompileError(f"match: references undefined placeholder ${name}")
        anchor = anchor_of[name]
        segs = next(s for (e, s) in part.placeholders[name] if e == anchor)
        sql, info, is_json = _plain_scalar(FieldRef(segments=segs), ctx, base=f"{_alias(anchor)}.event")
        return _typed(sql, info, is_json), name
    if isinstance(expr, FieldRef):
        evar = expr.prefix or part.evar_order[0]
        sql, info, is_json = _plain_scalar(FieldRef(segments=expr.segments), ctx, base=f"{_alias(evar)}.event")
        alias = "_".join(str(s.value) if isinstance(s, Key) else str(s) for s in expr.segments)
        return _typed(sql, info, is_json), alias
    raise UDMCompileError(f"Cannot use {type(expr).__name__} in match:")


# ---------------------------------------------------------------------------
# outcome: value compilation (incl. if())
# ---------------------------------------------------------------------------

def _rule_scalar(expr: Expr, ctx: CompileContext, part: _EventPartition, anchor_of: dict, default_evar: str):
    if isinstance(expr, VarRef):
        if expr.name in anchor_of:
            anchor = anchor_of[expr.name]
            segs = next(s for (e, s) in part.placeholders[expr.name] if e == anchor)
            return _plain_scalar(FieldRef(segments=segs), ctx, base=f"{_alias(anchor)}.event")
        raise UDMCompileError(f"Undefined variable ${expr.name}")
    if isinstance(expr, FieldRef):
        evar = expr.prefix or default_evar
        return _plain_scalar(FieldRef(segments=expr.segments), ctx, base=f"{_alias(evar)}.event")
    return _plain_scalar(expr, ctx, base=f"{_alias(default_evar)}.event")


def _if_operand_sql(expr: Expr, ctx, part, anchor_of, default_evar, outcome_names) -> str:
    if isinstance(expr, VarRef) and expr.name in outcome_names:
        return _alias(expr.name)  # already natively typed by its own SELECT expression
    if isinstance(expr, Literal):
        return _literal_sql(expr, ctx)  # already native SQL syntax; don't force a VARCHAR CAST
    sql, info, is_json = _rule_scalar(expr, ctx, part, anchor_of, default_evar)
    return _typed(sql, info, is_json)


def _compile_if_cond(expr: Expr, ctx, part, anchor_of, default_evar, outcome_names) -> str:
    if isinstance(expr, And):
        return "(" + " AND ".join(
            _compile_if_cond(c, ctx, part, anchor_of, default_evar, outcome_names) for c in expr.children
        ) + ")"
    if isinstance(expr, Or):
        return "(" + " OR ".join(
            _compile_if_cond(c, ctx, part, anchor_of, default_evar, outcome_names) for c in expr.children
        ) + ")"
    if isinstance(expr, Not):
        return f"NOT ({_compile_if_cond(expr.child, ctx, part, anchor_of, default_evar, outcome_names)})"
    if isinstance(expr, Comparison):
        op = _CMP_OPS.get(expr.op)
        if op is None:
            raise UDMCompileError(f"Unsupported operator {expr.op!r} in if()")
        l = _if_operand_sql(expr.left, ctx, part, anchor_of, default_evar, outcome_names)
        r = _if_operand_sql(expr.right, ctx, part, anchor_of, default_evar, outcome_names)
        return f"({l} {op} {r})"
    if isinstance(expr, FieldRef):
        sql, info, is_json = _rule_scalar(expr, ctx, part, anchor_of, default_evar)
        text = f"json_extract_string({sql}, '$')" if is_json else sql
        return f"({text} IS NOT NULL AND {text} != '')"
    raise UDMCompileError(f"Cannot compile {type(expr).__name__} in if()")


def _compile_rule_outcome_value(expr: Expr, ctx, part, anchor_of, default_evar, defined_outcome_names: set) -> str:
    """``defined_outcome_names`` are outcome variables assigned *earlier* in
    the same outcome: section -- valid to reference (as their SELECT
    alias) from a later assignment's if() condition, e.g. ``$risk_score =
    if($failed_count > 20, ...)`` after ``$failed_count = count(...)``."""
    if isinstance(expr, FuncCall):
        if expr.name == "if":
            if len(expr.args) != 3:
                raise UDMCompileError("if() expects exactly 3 arguments")
            cond_sql = _compile_if_cond(expr.args[0], ctx, part, anchor_of, default_evar, defined_outcome_names)
            then_sql = _compile_rule_outcome_value(expr.args[1], ctx, part, anchor_of, default_evar, defined_outcome_names)
            else_sql = _compile_rule_outcome_value(expr.args[2], ctx, part, anchor_of, default_evar, defined_outcome_names)
            return f"CASE WHEN {cond_sql} THEN {then_sql} ELSE {else_sql} END"
        template = _AGGREGATES.get(expr.name)
        if template is None:
            raise UDMCompileError(f"Unsupported outcome function {expr.name!r}")
        if len(expr.args) != 1:
            raise UDMCompileError(f"{expr.name}() expects exactly one argument")
        sql, info, is_json = _rule_scalar(expr.args[0], ctx, part, anchor_of, default_evar)
        arg_sql = _typed(sql, info, is_json)
        return template.format(arg_sql) if "{0}" in template else f"{template}({arg_sql})"
    if isinstance(expr, Literal):
        return _literal_sql(expr, ctx)  # already native SQL syntax; don't force a VARCHAR CAST
    if isinstance(expr, VarRef) and expr.name in defined_outcome_names:
        return _alias(expr.name)  # already natively typed by its own SELECT expression
    sql, info, is_json = _rule_scalar(expr, ctx, part, anchor_of, default_evar)
    return _typed(sql, info, is_json)


# ---------------------------------------------------------------------------
# condition: -> HAVING
# ---------------------------------------------------------------------------

def _compile_condition_bool(expr: Expr, outcome_names: set, ctx: CompileContext, gated: set) -> str:
    """``gated`` is the set of event variables compiled as a standalone
    top-level ``NOT EXISTS`` gate (no shared placeholder with anything
    else, referenced only negated) rather than joined in -- they have no
    table alias in scope here, so a reference to one is trivially true/
    false given the gate already enforced it."""
    if isinstance(expr, And):
        return "(" + " AND ".join(_compile_condition_bool(c, outcome_names, ctx, gated) for c in expr.children) + ")"
    if isinstance(expr, Or):
        return "(" + " OR ".join(_compile_condition_bool(c, outcome_names, ctx, gated) for c in expr.children) + ")"
    if isinstance(expr, Not):
        if isinstance(expr.child, EventRef) and expr.child.name in gated:
            return "TRUE"  # the NOT EXISTS gate already enforces this
        return f"NOT ({_compile_condition_bool(expr.child, outcome_names, ctx, gated)})"
    if isinstance(expr, EventRef):
        if expr.name in gated:
            raise UDMCompileError(
                f"event variable ${expr.name} has no shared placeholder "
                f"with any other event variable, so it can only be used "
                f"negated (!${expr.name}) in condition:"
            )
        return f"(count({_alias(expr.name)}.event) > 0)"
    if isinstance(expr, EventCount):
        return f"(count(DISTINCT {_alias(expr.name)}.event) > 0)"
    if isinstance(expr, Comparison):
        op = _CMP_OPS.get(expr.op)
        if op is None:
            raise UDMCompileError(f"Unsupported operator {expr.op!r} in condition:")
        left = _compile_condition_operand(expr.left, outcome_names, ctx)
        right = _compile_condition_operand(expr.right, outcome_names, ctx)
        return f"({left} {op} {right})"
    raise UDMCompileError(f"Cannot compile {type(expr).__name__} in condition:")


def _compile_condition_operand(expr: Expr, outcome_names: set, ctx: CompileContext) -> str:
    if isinstance(expr, EventCount):
        return f"count(DISTINCT {_alias(expr.name)}.event)"
    if isinstance(expr, VarRef):
        if expr.name in outcome_names:
            return _alias(expr.name)
        raise UDMCompileError(f"condition: references unknown outcome variable ${expr.name}")
    if isinstance(expr, Literal):
        return _literal_sql(expr, ctx)
    raise UDMCompileError(f"Cannot use {type(expr).__name__} as a condition: operand")


# ---------------------------------------------------------------------------
# Top level
# ---------------------------------------------------------------------------

def compile_rule(rule: Rule, schema: UDMSchema, params: Optional[dict] = None) -> str:
    """Compile a parsed :class:`~nudm.rule_nodes.Rule` to a DuckDB SQL
    statement, assuming a relation named ``events`` with ``name VARCHAR,
    event JSON`` columns (see :mod:`nudm.fake_data`)."""
    params = params or {}
    if "suppression_window" in rule.options:
        raise UDMCompileError(
            "options: suppression_window is not supported -- it requires "
            "persistent state across rule runs, which this stateless "
            "compile-and-run engine doesn't have"
        )
    _check_no_graph_fields(rule)

    part = _partition_events(rule)

    polarity: dict = {}
    _condition_evar_polarity(rule.condition, False, polarity)
    for name in polarity:
        if name not in part.evar_order:
            raise UDMCompileError(f"condition: references undefined event variable ${name}")

    window_seconds: Optional[int] = None
    pivot: Optional[tuple] = None
    for item in rule.match:
        g = item.grain
        if g is None:
            continue
        if g.anchor is None:
            if window_seconds is None:
                secs = _UNIT_SECONDS.get(g.unit)
                if secs is None:
                    raise UDMCompileError(f"Unsupported match: time unit {g.unit!r}")
                window_seconds = secs * g.quantity
        elif pivot is None:
            if g.pivot != part.evar_order[0]:
                raise UDMCompileError(
                    "match: 'before'/'after' pivot must be the first event "
                    f"variable declared in events: (got ${g.pivot}, expected "
                    f"${part.evar_order[0]})"
                )
            pivot = (g.anchor, g.pivot, g.quantity, g.unit)

    needs_bucket = window_seconds is not None

    anchor_of = {
        name: min(occs, key=lambda o: part.evar_order.index(o[0]))[0]
        for name, occs in part.placeholders.items()
    }

    ctx = CompileContext(schema=schema, params=params, events={})

    cte_sql_by_evar = {}
    where_sql_by_evar = {}
    for evar in part.evar_order:
        own_ph = [(n, s) for n, occs in part.placeholders.items() for (e, s) in occs if e == evar]
        cte_sql, where_sql = _cte_sql(
            evar, part.filters.get(evar, []), own_ph, needs_bucket, window_seconds, schema, ctx,
        )
        cte_sql_by_evar[evar] = cte_sql
        where_sql_by_evar[evar] = where_sql

    from_evar, joins, not_exists_evars = _build_joins(part, anchor_of, polarity)

    if pivot is not None and pivot[1] != from_evar:
        raise UDMCompileError(
            "match: 'before'/'after' pivot must be the first event variable "
            f"declared in events: (got ${pivot[1]}, expected ${from_evar})"
        )

    select_parts = []
    group_by = []
    for item in rule.match:
        col_sql, alias = _match_column(item, part, anchor_of, ctx)
        if item.grain and item.grain.first and needs_bucket and item.grain.anchor is None:
            col_sql = f'to_timestamp({_alias(from_evar)}.{_alias("_bucket")} * {window_seconds})'
        select_parts.append(f"{col_sql} AS {_alias(alias)}")
        group_by.append(_alias(alias))

    outcome_names = {a.name for a in rule.outcome}
    defined_so_far: set = set()
    for assign in rule.outcome:
        val_sql = _compile_rule_outcome_value(assign.value, ctx, part, anchor_of, from_evar, defined_so_far)
        select_parts.append(f"{val_sql} AS {_alias(assign.name)}")
        defined_so_far.add(assign.name)

    if not select_parts:
        # No match:/outcome: columns: condition:'s HAVING clause (built
        # below) still forces this into an aggregate query, so a raw
        # per-row column like "event" can't be selected without a GROUP BY
        # -- report how many detections' worth of rows correlated instead.
        select_parts.append(f'count(DISTINCT {_alias(from_evar)}.event) AS {_alias("matches")}')

    cte_defs = [f"{_alias(ev)} AS ({cte_sql_by_evar[ev]})" for ev in part.evar_order]
    sql = "WITH " + ", ".join(cte_defs) + f" SELECT {', '.join(select_parts)} FROM {_alias(from_evar)}"

    for evar, preds in joins:
        all_preds = list(preds)
        if needs_bucket:
            all_preds.append(f'{_alias(evar)}.{_alias("_bucket")} = {_alias(from_evar)}.{_alias("_bucket")}')
        if pivot is not None and evar != pivot[1]:
            all_preds.append(_pivot_predicate(evar, pivot))
        sql += f" LEFT JOIN {_alias(evar)} ON " + " AND ".join(all_preds)

    where_parts = []
    for evar in not_exists_evars:
        gate = where_sql_by_evar.get(evar)
        inner = f" WHERE {gate}" if gate else ""
        where_parts.append(f"NOT EXISTS (SELECT 1 FROM events{inner})")
    if where_parts:
        sql += " WHERE " + " AND ".join(where_parts)

    if group_by:
        sql += " GROUP BY " + ", ".join(group_by)

    having_sql = _compile_condition_bool(rule.condition, outcome_names, ctx, set(not_exists_evars))
    sql += f" HAVING {having_sql}"

    return sql
