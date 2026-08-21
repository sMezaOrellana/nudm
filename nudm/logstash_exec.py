"""Interpreter for the SecOps parser dialect: runs a parsed
``filter { ... }`` program over raw log messages and produces UDM event
dicts.

Execution model (deliberately different from the other two dialects, which
compile to SQL): a parser is a row-level stateful transformation pipeline,
so it is interpreted directly in Python. Each raw message starts as a state
dict ``{"message": <raw>, "@createTimestamp": ..., "@timezone": "UTC"}``;
plugins mutate that state; ``merge => { "@output" => "event" }`` appends
the ``event`` subtree to the output list; at the end, every output entry's
``idm.read_only_udm`` subtree becomes one UDM event (snake_case paths, the
same shape :func:`nudm.load_events` accepts).

Semantics notes:

* Dotted strings in plugin targets (``"event.idm.read_only_udm.principal.ip"``)
  are nested paths; bracket references in conditionals (``[network][source]``)
  traverse the same nesting.
* Reading a field that was never set raises :class:`UDMParserExecError` --
  the real engine crashes on uninitialized fields, and the docs' answer is
  to initialize everything at the top of the parser.
* ``on_error => "flag"`` on any plugin sets ``flag`` to ``True`` on failure
  and ``False`` on success; without it, a failure raises.
* Inside one ``mutate`` block, operations run in the order the Logstash
  mutate plugin documents (restricted to the operations SecOps supports):
  rename, replace, convert, gsub, uppercase, lowercase, split, merge, copy;
  ``remove_field`` (a Logstash "common option") runs last.
* ``merge`` accumulates: merging into a set field turns it into a list --
  this is how repeated UDM fields and label lists are built.
* Not supported: the ``xml`` plugin (rejected at parse time).
"""
from __future__ import annotations

import base64
import copy as copy_module
import datetime
import ipaddress
import json
import re
import sys
from typing import Any, Iterable, Optional
from zoneinfo import ZoneInfo

from .grok_patterns import GrokError, compile_grok
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
from .logstash_parser import parse_parser
from .schema import UDMSchema

_MISSING = object()

UDM_PREFIXES = (
    "event.idm.read_only_udm.",
    "event1.idm.read_only_udm.",
    "event2.idm.read_only_udm.",
)


class UDMParserExecError(ValueError):
    """Raised when a parser crashes at run time (an uninitialized field read,
    a plugin failure with no ``on_error``, an unsupported construct)."""


class _PluginFailure(Exception):
    """Internal: a plugin failed in a way ``on_error`` may absorb."""


class _Ctx:
    def __init__(self, state: dict):
        self.state = state
        self.dropped = False
        self.drop_tag: Optional[str] = None


# ---------------------------------------------------------------------------
# Top-level API
# ---------------------------------------------------------------------------

def run_parser(
    parser: Parser | str,
    raw_logs: Iterable[Any],
    *,
    schema: Optional[UDMSchema] | bool = None,
) -> list[dict]:
    """Run a parser over raw logs and return the produced UDM events (a list
    of nested snake_case UDM dicts, ready for :func:`nudm.load_events`).

    ``parser`` is a :class:`~nudm.logstash_nodes.Parser` or raw parser text.
    ``raw_logs`` is an iterable of raw message strings, or dicts with a
    ``message`` key plus system variables (``@timestamp``,
    ``@collectionTimestamp``, ...). A single ``str`` is treated as one raw
    message.

    ``schema`` controls schema-awareness (same role as the query/rule
    compilers' schema checks): with a :class:`UDMSchema` (the default, loaded
    lazily), static ``event.idm.read_only_udm.*`` targets are validated
    against the UDM field dictionary and ``repeated`` UDM fields are wrapped
    in arrays in the output (matching how the real engine serializes UDM --
    without it, a repeated field stored as a scalar object won't be found by
    queries). Pass ``schema=False`` to skip both.
    """
    if isinstance(parser, str):
        parser = parse_parser(parser)
    if schema is None:
        schema = _default_schema()
    if isinstance(raw_logs, str):
        raw_logs = [raw_logs]
    events: list[dict] = []
    if schema:
        _check_udm_paths(parser.statements, schema)
    for raw in raw_logs:
        events.extend(_run_one(parser, raw, schema or None))
    return events


_default_schema_instance: Optional[UDMSchema] = None


def _default_schema() -> UDMSchema:
    global _default_schema_instance
    if _default_schema_instance is None:
        _default_schema_instance = UDMSchema()
    return _default_schema_instance


def _run_one(parser: Parser, raw: Any, schema: Optional[UDMSchema]) -> list[dict]:
    if isinstance(raw, dict):
        message = raw.get("message", "")
        extras = {k: v for k, v in raw.items() if k != "message"}
    else:
        message = str(raw)
        extras = {}
    state: dict = {
        "message": message,
        "@createTimestamp": _format_udm_ts(datetime.datetime.now(datetime.UTC)),
        "@timezone": "UTC",
        "@onErrorCount": 0,
    }
    state.update(extras)
    ctx = _Ctx(state)
    _exec_stmts(parser.statements, ctx)
    if ctx.dropped:
        return []
    return _collect_outputs(ctx, schema)


# ---------------------------------------------------------------------------
# State path helpers
# ---------------------------------------------------------------------------

def _get(state: dict, segments: list[str] | tuple[str, ...]) -> Any:
    cur: Any = state
    for seg in segments:
        if isinstance(cur, dict) and seg in cur:
            cur = cur[seg]
        else:
            return _MISSING
    return cur


def _set(state: dict, segments: list[str] | tuple[str, ...], value: Any) -> None:
    cur = state
    for seg in segments[:-1]:
        nxt = cur.get(seg)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[seg] = nxt
        cur = nxt
    cur[segments[-1]] = value


def _delete(state: dict, segments: list[str] | tuple[str, ...]) -> None:
    cur: Any = state
    for seg in segments[:-1]:
        if not isinstance(cur, dict) or seg not in cur:
            return
        cur = cur[seg]
    if isinstance(cur, dict):
        cur.pop(segments[-1], None)


def _require(ctx: _Ctx, segments: list[str] | tuple[str, ...]) -> Any:
    value = _get(ctx.state, segments)
    if value is _MISSING:
        raise UDMParserExecError(
            f"field {'.'.join(segments)} is not set; SecOps parsers crash on "
            "uninitialized fields -- initialize it at the top of the parser "
            '(mutate { replace => { "..." => "" } }) or extract it first'
        )
    return value


def _segments(name: str) -> list[str]:
    return name.split(".")


_INTERP = re.compile(r"%\{([^}]+)\}")


def _interp(ctx: _Ctx, text: str) -> str:
    """Resolve ``%{token}`` references; unresolved (missing) references are
    left literal, matching Logstash sprintf behavior."""
    def sub(m: re.Match) -> str:
        name = m.group(1)
        if name.startswith("["):
            segments = re.findall(r"\[([^\]]+)\]", name)
        else:
            segments = name.split(".")
        value = _get(ctx.state, segments)
        if value is _MISSING:
            return m.group(0)
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (dict, list)):
            return json.dumps(value)
        return str(value)

    return _INTERP.sub(sub, text)


# ---------------------------------------------------------------------------
# Statement execution
# ---------------------------------------------------------------------------

def _exec_stmts(stmts: tuple[Stmt, ...], ctx: _Ctx) -> None:
    for stmt in stmts:
        _exec_stmt(stmt, ctx)


def _exec_stmt(stmt: Stmt, ctx: _Ctx) -> None:
    if isinstance(stmt, IfStmt):
        if _truthy(_eval_cond(stmt.cond, ctx)):
            _exec_stmts(stmt.then_body, ctx)
        elif stmt.else_body:
            _exec_stmts(stmt.else_body, ctx)
    elif isinstance(stmt, ForStmt):
        _exec_for(stmt, ctx)
    elif isinstance(stmt, PluginCall):
        _exec_plugin(stmt, ctx)


def _exec_for(stmt: ForStmt, ctx: _Ctx) -> None:
    iterable = _require(ctx, [stmt.iterable])
    pairs: list[tuple[Any, Any]] = []
    if stmt.is_map:
        if not isinstance(iterable, dict):
            raise UDMParserExecError(
                f"for ... in {stmt.iterable} map: {stmt.iterable} is not an object"
            )
        pairs = list(iterable.items())
    elif isinstance(iterable, dict):
        pairs = list(enumerate(iterable.values()))
    elif isinstance(iterable, list):
        pairs = list(enumerate(iterable))
    else:
        raise UDMParserExecError(
            f"for ... in {stmt.iterable}: {stmt.iterable} is not iterable "
            "(arrays come from json split_columns, mutate.split, or grok match_all)"
        )

    if len(stmt.loop_vars) == 1:
        set_names = [stmt.loop_vars[0]]
        items = [(v,) if not stmt.is_map else (v,) for _, v in pairs]
    else:
        set_names = list(stmt.loop_vars)
        items = list(pairs)

    for values in items:
        for name, value in zip(set_names, values):
            ctx.state[name] = value
        _exec_stmts(stmt.body, ctx)
    for name in set_names:
        ctx.state.pop(name, None)


# ---------------------------------------------------------------------------
# Conditionals
# ---------------------------------------------------------------------------

def _eval_cond(expr: CondExpr, ctx: _Ctx) -> Any:
    if isinstance(expr, And):
        return all(_truthy(_eval_cond(c, ctx)) for c in expr.children)
    if isinstance(expr, Or):
        return any(_truthy(_eval_cond(c, ctx)) for c in expr.children)
    if isinstance(expr, Not):
        return not _truthy(_eval_cond(expr.child, ctx))
    if isinstance(expr, FieldRef):
        return _require(ctx, list(expr.segments))
    if isinstance(expr, Comparison):
        return _compare(expr, ctx)
    raise UDMParserExecError(f"cannot evaluate conditional {expr!r}")


def _operand_value(operand: CondExpr, ctx: _Ctx) -> Any:
    if isinstance(operand, FieldRef):
        return _require(ctx, list(operand.segments))
    if isinstance(operand, Literal):
        return operand.value
    if isinstance(operand, ArrayLit):
        return [_operand_value(Literal(v) if not isinstance(v, CondExpr) else v, ctx)
                for v in operand.items]
    raise UDMParserExecError(f"cannot evaluate operand {operand!r}")


def _try_num(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _eq(a: Any, b: Any) -> bool:
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    na, nb = _try_num(a), _try_num(b)
    if na is not None and nb is not None:
        return na == nb
    return a == b


def _compare(expr: Comparison, ctx: _Ctx) -> bool:
    left = _operand_value(expr.left, ctx)
    right = _operand_value(expr.right, ctx)
    op = expr.op
    if op == "==":
        return _eq(left, right)
    if op == "!=":
        return not _eq(left, right)
    if op == "=~":
        return re.search(str(right), str(left)) is not None
    if op == "!~":
        return re.search(str(right), str(left)) is None
    if op == "in":
        if not isinstance(right, list):
            raise UDMParserExecError("'in' requires an array on the right side")
        return any(_eq(left, item) for item in right)
    # ordering operators
    na, nb = _try_num(left), _try_num(right)
    if na is not None and nb is not None:
        a, b = na, nb
    else:
        a, b = str(left), str(right)
    if op == "<":
        return a < b
    if op == ">":
        return a > b
    if op == "<=":
        return a <= b
    return a >= b


def _truthy(value: Any) -> bool:
    return bool(value)


# ---------------------------------------------------------------------------
# Plugin dispatch
# ---------------------------------------------------------------------------

def _exec_plugin(call: PluginCall, ctx: _Ctx) -> None:
    on_error = call.args.get("on_error")
    try:
        _PLUGINS[call.name](call.args, ctx)
    except _PluginFailure as exc:
        if on_error:
            _set(ctx.state, _segments(str(on_error)), True)
            ctx.state["@onErrorCount"] = ctx.state.get("@onErrorCount", 0) + 1
        else:
            raise UDMParserExecError(f"{call.name} failed: {exc}") from exc
    else:
        if on_error:
            _set(ctx.state, _segments(str(on_error)), False)


def _fail(message: str) -> Any:
    raise _PluginFailure(message)


def _str_arg(args: dict, name: str, default: Optional[str] = None) -> Optional[str]:
    value = args.get(name, default)
    if value is None:
        return None
    return str(value)


# ---------------------------------------------------------------------------
# Extraction plugins
# ---------------------------------------------------------------------------

def _plugin_grok(args: dict, ctx: _Ctx) -> None:
    match = args.get("match")
    if not isinstance(match, dict) or not match:
        _fail('grok requires match => { "source" => "pattern" }')
    match_all = bool(args.get("match_all"))
    overwrite = set(args.get("overwrite") or [])

    for source, patterns in match.items():
        if isinstance(patterns, str):
            patterns = [patterns]
        text = _require(ctx, _segments(str(source)))
        if not isinstance(text, str):
            _fail(f"grok source {source!r} is not a string")

        compiled = []
        for pattern in patterns:
            try:
                compiled.append(compile_grok(str(pattern)))
            except GrokError as exc:
                _fail(str(exc))

        if match_all:
            rx, labels = next(
                ((rx, labels) for rx, labels in compiled if rx.search(text)),
                (None, ()),
            )
            if rx is None:
                _fail(f"grok pattern did not match {source!r}")
            collected: dict[str, dict[str, str]] = {label: {} for label in labels}
            for i, m in enumerate(rx.finditer(text)):
                for label in labels:
                    value = m.group(label)
                    if value is not None:
                        collected[label][str(i)] = value
            for label, value in collected.items():
                _grok_store(ctx, label, value, overwrite)
        else:
            hit = None
            for rx, labels in compiled:
                m = rx.search(text)
                if m is not None:
                    hit = (m, labels)
                    break
            if hit is None:
                _fail(f"grok pattern did not match {source!r}")
            m, labels = hit
            for label in labels:
                value = m.group(label)
                if value is not None:
                    _grok_store(ctx, label, value, overwrite)


def _grok_store(ctx: _Ctx, label: str, value: Any, overwrite: set[str]) -> None:
    segments = _segments(label)
    if label not in overwrite and _get(ctx.state, segments) is not _MISSING:
        _fail(
            f"grok token {label!r} already exists; declare it in overwrite "
            "=> [...] to replace it"
        )
    _set(ctx.state, segments, value)


def _plugin_json(args: dict, ctx: _Ctx) -> None:
    source = _str_arg(args, "source", "message")
    text = _require(ctx, _segments(source))
    if not isinstance(text, str):
        _fail(f"json source {source!r} is not a string")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        _fail(f"invalid JSON in {source!r}: {exc}")
    if not isinstance(data, dict):
        _fail(f"json source {source!r} is not a JSON object")
    if _str_arg(args, "array_function") == "split_columns":
        data = _split_columns(data)
    for key, value in data.items():
        ctx.state[key] = value


def _split_columns(value: Any) -> Any:
    """Recursively turn arrays into index-keyed objects:
    ``{"ips": ["a", "b"]}`` -> ``{"ips": {"0": "a", "1": "b"}}``."""
    if isinstance(value, dict):
        return {k: _split_columns(v) for k, v in value.items()}
    if isinstance(value, list):
        return {str(i): _split_columns(v) for i, v in enumerate(value)}
    return value


def _plugin_kv(args: dict, ctx: _Ctx) -> None:
    source = _str_arg(args, "source", "message")
    field_split = _str_arg(args, "field_split", " ")
    value_split = _str_arg(args, "value_split", "=")
    whitespace = _str_arg(args, "whitespace", "lenient")
    trim_value = _str_arg(args, "trim_value", "")
    text = _require(ctx, _segments(source))
    if not isinstance(text, str):
        _fail(f"kv source {source!r} is not a string")
    for pair in text.split(field_split):
        if value_split not in pair:
            continue
        key, value = pair.split(value_split, 1)
        if whitespace == "lenient":
            key = key.strip()
            value = value.strip()
        if trim_value:
            value = value.strip(trim_value)
        if key:
            ctx.state[key] = value


def _plugin_csv(args: dict, ctx: _Ctx) -> None:
    import csv as csv_module

    source = _str_arg(args, "source", "message")
    separator = _str_arg(args, "separator", ",")
    if len(separator) != 1:
        _fail("csv separator must be a single character")
    text = _require(ctx, _segments(source))
    if not isinstance(text, str):
        _fail(f"csv source {source!r} is not a string")
    try:
        row = next(csv_module.reader([text], delimiter=separator))
    except (csv_module.Error, StopIteration) as exc:
        _fail(f"csv parse failed: {exc}")
    for i, value in enumerate(row, start=1):
        ctx.state[f"column{i}"] = value


# ---------------------------------------------------------------------------
# mutate
# ---------------------------------------------------------------------------

# Logstash mutate plugin's documented execution order, restricted to the
# operations the SecOps parser supports; remove_field is a Logstash "common
# option" and runs after the main operations.
_MUTATE_ORDER = (
    "rename", "replace", "convert", "gsub", "uppercase", "lowercase",
    "split", "merge", "copy", "remove_field",
)


def _plugin_mutate(args: dict, ctx: _Ctx) -> None:
    for op in _MUTATE_ORDER:
        if op in args:
            _MUTATE_OPS[op](args[op], ctx)


def _mutate_rename(spec: Any, ctx: _Ctx) -> None:
    for src, dst in _hash_spec(spec, "rename").items():
        src_segs, dst_segs = _segments(str(src)), _segments(str(dst))
        value = _get(ctx.state, src_segs)
        if value is _MISSING:
            continue  # logstash: missing source is not an error
        _delete(ctx.state, src_segs)
        _set(ctx.state, dst_segs, value)


def _mutate_replace(spec: Any, ctx: _Ctx) -> None:
    for dst, value in _hash_spec(spec, "replace").items():
        dst = _interp(ctx, str(dst))
        if isinstance(value, str):
            value = _interp(ctx, value)
        elif isinstance(value, bool):
            value = "true" if value else "false"
        elif not isinstance(value, (int, float)):
            value = str(value)
        _set(ctx.state, _segments(dst), value)


def _mutate_convert(spec: Any, ctx: _Ctx) -> None:
    for field, target in _hash_spec(spec, "convert").items():
        segments = _segments(str(field))
        value = _require(ctx, segments)
        target = str(target)
        if isinstance(value, list):
            _set(ctx.state, segments, [_convert_one(v, target, field) for v in value])
        else:
            _set(ctx.state, segments, _convert_one(value, target, field))


def _convert_one(value: Any, target: str, field: str) -> Any:
    try:
        if target == "string":
            if isinstance(value, bool):
                return "true" if value else "false"
            return str(value)
        if target == "integer":
            if isinstance(value, bool):
                return int(value)
            if isinstance(value, (int, float)):
                return int(value)
            return int(float(str(value).replace(",", "")))
        if target == "uinteger":
            result = _convert_one(value, "integer", field)
            if result < 0:
                _fail(f"convert {field!r} to uinteger: negative value {value!r}")
            return result
        if target == "float":
            if isinstance(value, bool):
                return float(value)
            if isinstance(value, (int, float)):
                return float(value)
            return float(str(value).replace(",", ""))
        if target == "boolean":
            return _to_boolean(value, field)
        if target == "hextodec":
            return int(str(value), 16)
        if target == "hextoascii":
            return bytes.fromhex(str(value).replace(" ", "")).decode("ascii")
        if target == "hash":
            if isinstance(value, list) and len(value) % 2 == 0:
                return dict(zip(value[::2], value[1::2]))
            _fail(f"convert {field!r} to hash: value must be an even-length array")
        if target == "ipaddress":
            ipaddress.ip_address(str(value))  # rejects leading-zero/hex/decimal forms
            return str(value)
        if target == "macaddress":
            if not re.fullmatch(
                r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"
                r"|([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}",
                str(value),
            ):
                _fail(f"convert {field!r} to macaddress: {value!r} is not a MAC")
            return str(value)
    except (ValueError, TypeError) as exc:
        _fail(f"convert {field!r} to {target}: {value!r}: {exc}")
    _fail(f"convert: unsupported target type {target!r}")


def _to_boolean(value: Any, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if value in (0, 0.0):
            return False
        if value in (1, 1.0):
            return True
        _fail(f"convert {field!r} to boolean: {value!r}")
    if isinstance(value, str):
        if value.lower() in ("true", "t", "yes", "y", "1", "1.0") or value == "":
            return bool(value) and value != ""
        if value.lower() in ("false", "f", "no", "n", "0", "0.0"):
            return False
    _fail(f"convert {field!r} to boolean: {value!r}")


def _mutate_gsub(spec: Any, ctx: _Ctx) -> None:
    if not isinstance(spec, list) or len(spec) % 3 != 0:
        _fail("gsub takes a flat array of triples: field, regex, replacement")
    for i in range(0, len(spec), 3):
        field, pattern, replacement = str(spec[i]), str(spec[i + 1]), str(spec[i + 2])
        segments = _segments(field)
        value = _get(ctx.state, segments)
        if value is _MISSING or not isinstance(value, str):
            continue  # logstash: no action on missing/non-string fields
        try:
            _set(ctx.state, segments, re.sub(pattern, replacement, value))
        except re.error as exc:
            _fail(f"gsub {field!r}: bad regex {pattern!r}: {exc}")


def _mutate_uppercase(spec: Any, ctx: _Ctx) -> None:
    _mutate_case(spec, ctx, str.upper, "uppercase")


def _mutate_lowercase(spec: Any, ctx: _Ctx) -> None:
    _mutate_case(spec, ctx, str.lower, "lowercase")


def _mutate_case(spec: Any, ctx: _Ctx, fn, op: str) -> None:
    if not isinstance(spec, list):
        _fail(f"{op} takes an array of field names")
    for field in spec:
        segments = _segments(str(field))
        value = _get(ctx.state, segments)
        if isinstance(value, str):
            _set(ctx.state, segments, fn(value))


def _mutate_split(spec: Any, ctx: _Ctx) -> None:
    if isinstance(spec, dict) and "source" in spec:
        # SecOps form: split => { source => "f" separator => "," target => "g" }
        source = str(spec["source"])
        separator = str(spec.get("separator", ","))
        target = str(spec.get("target", source))
    elif isinstance(spec, dict):
        # Logstash form: split => { "field" => "," }
        (source, separator), = ((str(k), str(v)) for k, v in spec.items())
        target = source
    else:
        _fail("split takes a hash: { source => ..., separator => ..., target => ... }")
    segments = _segments(source)
    value = _require(ctx, segments)
    if not isinstance(value, str):
        _fail(f"split {source!r}: value is not a string")
    _set(ctx.state, _segments(target), value.split(separator))


def _mutate_merge(spec: Any, ctx: _Ctx) -> None:
    for dst, src in _hash_spec(spec, "merge").items():
        dst, src = str(dst), str(src)
        value = _get(ctx.state, _segments(src))
        if value is _MISSING:
            # Docs: merge "silently skips nonexistent elements".
            continue
        if dst == "@output":
            if not isinstance(value, dict):
                _fail(f'merge "@output" => {src!r}: {src!r} is not an object')
            outputs = ctx.state.setdefault("@output", [])
            outputs.append(copy_module.deepcopy(value))
            continue
        dst_segs = _segments(dst)
        current = _get(ctx.state, dst_segs)
        if current is _MISSING:
            _set(ctx.state, dst_segs, copy_module.deepcopy(value))
        elif isinstance(current, list):
            if isinstance(value, list):
                current.extend(copy_module.deepcopy(value))
            else:
                current.append(copy_module.deepcopy(value))
        else:
            if isinstance(value, list):
                _set(ctx.state, dst_segs, [current, *copy_module.deepcopy(value)])
            else:
                _set(ctx.state, dst_segs, [current, copy_module.deepcopy(value)])


def _mutate_copy(spec: Any, ctx: _Ctx) -> None:
    for dst, src in _hash_spec(spec, "copy").items():
        src_segs, dst_segs = _segments(str(src)), _segments(str(dst))
        value = _require(ctx, src_segs)
        _set(ctx.state, dst_segs, copy_module.deepcopy(value))


def _mutate_remove_field(spec: Any, ctx: _Ctx) -> None:
    if not isinstance(spec, list):
        _fail("remove_field takes an array of field names")
    for field in spec:
        _delete(ctx.state, _segments(_interp(ctx, str(field))))


def _hash_spec(spec: Any, op: str) -> dict:
    if not isinstance(spec, dict) or not spec:
        _fail(f"{op} takes a non-empty hash")
    return spec


_MUTATE_OPS = {
    "rename": _mutate_rename,
    "replace": _mutate_replace,
    "convert": _mutate_convert,
    "gsub": _mutate_gsub,
    "uppercase": _mutate_uppercase,
    "lowercase": _mutate_lowercase,
    "split": _mutate_split,
    "merge": _mutate_merge,
    "copy": _mutate_copy,
    "remove_field": _mutate_remove_field,
}


# ---------------------------------------------------------------------------
# date / base64 / drop / statedump
# ---------------------------------------------------------------------------

def _plugin_date(args: dict, ctx: _Ctx) -> None:
    match = args.get("match")
    if not isinstance(match, list) or len(match) < 2:
        _fail('date requires match => ["token", "format", ...]')
    token, formats = str(match[0]), [str(f) for f in match[1:]]
    text = _require(ctx, _segments(token))
    if not isinstance(text, str):
        _fail(f"date: {token!r} is not a string")

    tz_name = _str_arg(args, "timezone") or str(ctx.state.get("@timezone", "UTC"))
    try:
        tz = ZoneInfo(tz_name)
    except Exception as exc:  # noqa: BLE001
        _fail(f"date: unknown timezone {tz_name!r}: {exc}")

    parsed = None
    for fmt in formats:
        parsed = _parse_date(text, fmt)
        if parsed is not None:
            dt, has_year = parsed
            break
    if parsed is None:
        _fail(f"date: {text!r} matched none of the formats {formats}")
    dt, has_year = parsed

    if args.get("rebase") and not has_year:
        created = str(ctx.state.get("@createTimestamp", ""))
        if created[:4].isdigit():
            dt = dt.replace(year=int(created[:4]))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz)

    target = _str_arg(args, "target") or "event.idm.read_only_udm.metadata.event_timestamp"
    _set(ctx.state, _segments(target), _format_udm_ts(dt))


def _parse_date(text: str, fmt: str) -> Optional[tuple[datetime.datetime, bool]]:
    try:
        if fmt == "UNIX":
            return datetime.datetime.fromtimestamp(float(text), datetime.UTC), True
        if fmt == "UNIX_MS":
            return datetime.datetime.fromtimestamp(float(text) / 1000, datetime.UTC), True
        if fmt in ("ISO8601", "RFC3339"):
            return datetime.datetime.fromisoformat(text.replace("Z", "+00:00")), True
        pyfmt = _java_to_strptime(fmt)
        if "yyyy" in fmt or "yy" in fmt:
            return datetime.datetime.strptime(text, pyfmt), True
        # Yearless format (e.g. syslog's "MMM dd HH:mm:ss"): parse with an
        # explicit dummy year (avoids strptime's ambiguous-default-year
        # behavior); ``rebase => true`` then sets the real year.
        return datetime.datetime.strptime(f"{text} 1900", f"{pyfmt} %Y"), False
    except (ValueError, OverflowError, OSError):
        return None


# Java-style date pattern tokens -> strptime, tried longest-first per
# position. Text in single quotes is literal (Java convention).
_JAVA_TOKENS = (
    ("yyyy", "%Y"), ("yy", "%y"),
    ("MMMM", "%B"), ("MMM", "%b"), ("MM", "%m"),
    ("dd", "%d"),
    ("HH", "%H"), ("hh", "%I"),
    ("mm", "%M"),
    ("SSS", "%f"), ("ss", "%S"),
    ("EEEE", "%A"), ("EEE", "%a"),
    ("XXX", "%z"), ("XX", "%z"), ("Z", "%z"),
    ("a", "%p"), ("A", "%p"),
)


def _java_to_strptime(fmt: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(fmt):
        ch = fmt[i]
        if ch == "'":
            end = fmt.find("'", i + 1)
            if end == -1:
                raise ValueError(f"unterminated quote in date format {fmt!r}")
            out.append(fmt[i + 1:end].replace("%", "%%"))
            i = end + 1
            continue
        for token, py in _JAVA_TOKENS:
            if fmt.startswith(token, i):
                out.append(py)
                i += len(token)
                break
        else:
            out.append("%%" if ch == "%" else ch)
            i += 1
    return "".join(out)


def _format_udm_ts(dt: datetime.datetime) -> str:
    return dt.astimezone(datetime.UTC).isoformat().replace("+00:00", "Z")


def _plugin_base64(args: dict, ctx: _Ctx) -> None:
    source = _str_arg(args, "source")
    target = _str_arg(args, "target")
    if not source or not target:
        _fail("base64 requires source and target")
    encoding = _str_arg(args, "encoding", "Standard")
    text = _require(ctx, _segments(source))
    if not isinstance(text, str):
        _fail(f"base64 source {source!r} is not a string")
    try:
        if encoding == "Standard":
            raw = base64.b64decode(text)
        elif encoding == "RawStandard":
            raw = base64.b64decode(text + "=" * (-len(text) % 4))
        elif encoding == "URL":
            raw = base64.urlsafe_b64decode(text)
        elif encoding == "RawURL":
            raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        else:
            _fail(f"base64: unsupported encoding {encoding!r}")
        _set(ctx.state, _segments(target), raw.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        _fail(f"base64 decode of {source!r} failed: {exc}")


def _plugin_drop(args: dict, ctx: _Ctx) -> None:
    ctx.dropped = True
    ctx.drop_tag = _str_arg(args, "tag")


def _plugin_statedump(args: dict, ctx: _Ctx) -> None:
    print(
        json.dumps({"statedump": args.get("label"), "state": ctx.state},
                   default=str),
        file=sys.stderr,
    )


_PLUGINS = {
    "grok": _plugin_grok,
    "json": _plugin_json,
    "kv": _plugin_kv,
    "csv": _plugin_csv,
    "mutate": _plugin_mutate,
    "date": _plugin_date,
    "base64": _plugin_base64,
    "drop": _plugin_drop,
    "statedump": _plugin_statedump,
}


# ---------------------------------------------------------------------------
# Output collection
# ---------------------------------------------------------------------------

def _collect_outputs(ctx: _Ctx, schema: Optional[UDMSchema]) -> list[dict]:
    outputs = ctx.state.get("@output")
    if not isinstance(outputs, list):
        return []
    events: list[dict] = []
    for entry in outputs:
        if not isinstance(entry, dict):
            continue
        idm = entry.get("idm")
        udm = idm.get("read_only_udm") if isinstance(idm, dict) else None
        if not isinstance(udm, dict):
            continue
        udm = copy_module.deepcopy(udm)
        ts = ctx.state.get("@timestamp")
        if ts and "event_timestamp" not in udm.get("metadata", {}):
            udm.setdefault("metadata", {})["event_timestamp"] = _normalize_ts(ts)
        if schema is not None:
            udm = _shape_repeated(udm, (), schema)
        events.append(udm)
    return events


def _shape_repeated(node: Any, path: tuple[str, ...], schema: UDMSchema) -> Any:
    """Recursively wrap ``repeated`` UDM fields in arrays, matching how UDM
    JSON is really serialized (and how the query compiler expects to find
    it): a parser mapping ``security_result.action`` once must still produce
    ``security_result: [{...}]``. Values already built up as lists (via
    repeated ``merge``) are left alone; unknown/dynamic paths are untouched.
    """
    if not isinstance(node, dict):
        return node
    out = {}
    for key, value in node.items():
        child_path = path + (key,)
        if isinstance(value, dict):
            value = _shape_repeated(value, child_path, schema)
        elif isinstance(value, list):
            value = [_shape_repeated(v, child_path, schema) for v in value]
        info = schema.lookup(".".join(child_path))
        if info is not None and info.repeated and not isinstance(value, list):
            value = [value]
        out[key] = value
    return out


def _normalize_ts(value: Any) -> str:
    if isinstance(value, datetime.datetime):
        return _format_udm_ts(value)
    return str(value)


# ---------------------------------------------------------------------------
# Schema-aware target validation (the analog of compile-time field checks
# for the query/rule dialects)
# ---------------------------------------------------------------------------

def _check_udm_paths(stmts: tuple[Stmt, ...], schema: UDMSchema) -> None:
    from .duckdb_sql import UDMCompileError

    for stmt in stmts:
        if isinstance(stmt, PluginCall):
            if stmt.name == "mutate":
                _check_mutate_udm_paths(stmt.args, schema)
        elif isinstance(stmt, IfStmt):
            _check_udm_paths(stmt.then_body, schema)
            if stmt.else_body:
                _check_udm_paths(stmt.else_body, schema)
        elif isinstance(stmt, ForStmt):
            _check_udm_paths(stmt.body, schema)


def _check_mutate_udm_paths(args: dict, schema: UDMSchema) -> None:
    from .duckdb_sql import UDMCompileError

    # Operation -> which side of each pair is the destination field.
    targets: list[tuple[str, str]] = [
        ("replace", "keys"), ("rename", "values"), ("merge", "keys"),
        ("copy", "keys"),
    ]
    for op, side in targets:
        spec = args.get(op)
        if not isinstance(spec, dict):
            continue
        items = spec.keys() if side == "keys" else spec.values()
        for item in items:
            if not isinstance(item, str) or "%{" in item:
                continue
            for prefix in UDM_PREFIXES:
                if not item.startswith(prefix):
                    continue
                path = item[len(prefix):]
                info = schema.lookup(path)
                if info is None:
                    raise UDMCompileError(
                        f"parser references unknown UDM field {path!r}"
                    )
                if op == "replace":
                    value = spec[item]
                    if (isinstance(value, str) and "%{" not in value
                            and info.enum
                            and value not in (schema.enum_values(info.type) or ())):
                        raise UDMCompileError(
                            f"{value!r} is not a valid {info.type} member "
                            f"for UDM field {path!r}"
                        )
