"""Top-level convenience: UDM query text -> DuckDB-executed -> API-shaped
JSON result, against fake event data already loaded via
:mod:`nudm.fake_data`."""
from __future__ import annotations

from typing import Optional

from .duckdb_sql import compile_query
from .parser import parse
from .response import build_event_response, build_result_response
from .rule_parser import parse_rule
from .rule_sql import compile_rule
from .schema import UDMSchema

_schema: Optional[UDMSchema] = None


def _default_schema() -> UDMSchema:
    global _schema
    if _schema is None:
        _schema = UDMSchema()
    return _schema


def search(
    query_text: str, conn, *,
    schema: Optional[UDMSchema] = None,
    params: Optional[dict[str, str]] = None,
) -> dict:
    """Parse ``query_text``, compile it to SQL, run it against ``conn``
    (a DuckDB connection with fake events already loaded via
    :func:`nudm.fake_data.load_events`), and return the result reshaped
    into the real API's response JSON."""
    query = parse(query_text)
    result = compile_query(query, schema or _default_schema(), params)
    cursor = conn.execute(result)
    rows = cursor.fetchall()
    if query.match or query.outcome:
        column_names = [d[0] for d in cursor.description]
        return build_result_response(rows, column_names)
    return build_event_response(rows)


def run_rule(
    rule_text: str, conn, *,
    schema: Optional[UDMSchema] = None,
    params: Optional[dict[str, str]] = None,
) -> dict:
    """Parse a YARA-L 2.0 rule (``rule name { ... }``), compile it to SQL,
    run it against ``conn``, and return the detections reshaped into a
    ``{"results": [...]}`` envelope (same shape as a match+outcome UDM
    query's result, since a rule's output -- correlated/grouped detections
    -- is structurally identical)."""
    rule = parse_rule(rule_text)
    result = compile_rule(rule, schema or _default_schema(), params)
    cursor = conn.execute(result)
    rows = cursor.fetchall()
    column_names = [d[0] for d in cursor.description]
    return build_result_response(rows, column_names)
