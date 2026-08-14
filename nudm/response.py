"""Reshape DuckDB query results back into the real Google SecOps API's
response JSON shape: camelCase keys, ``{"events": [...]}`` envelope for raw
event searches.

Fake events are stored keyed by snake_case canonical UDM paths (matching
the query language), so this module is the *only* place that does
snake_case -> camelCase conversion -- it happens once, on the way out.
"""
from __future__ import annotations

import datetime
import json
import re
from typing import Any

_UNDERSCORE_RUN = re.compile(r"_+([a-zA-Z0-9])")


def to_camel_case(name: str) -> str:
    """``event_type`` -> ``eventType``. Leading underscores are preserved."""
    return _UNDERSCORE_RUN.sub(lambda m: m.group(1).upper(), name)


def camelize(value: Any) -> Any:
    """Recursively convert dict keys from snake_case to camelCase."""
    if isinstance(value, dict):
        return {to_camel_case(k): camelize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [camelize(v) for v in value]
    if isinstance(value, (datetime.datetime, datetime.date)):
        return value.isoformat()
    return value


def build_event_response(rows: list[tuple]) -> dict:
    """Build ``{"events": [{"name": ..., "udm": {...}}, ...]}`` from rows of
    a plain (non-aggregate) query, where each row is ``(name, event_json)``.
    """
    events = [
        {"name": name, "udm": camelize(json.loads(event_json))}
        for name, event_json in rows
    ]
    return {"events": events}


def build_result_response(rows: list[tuple], column_names: list[str]) -> dict:
    """Build a result envelope for a match/outcome (aggregation) query.

    Note: the real API's actual stats-response envelope isn't nailed down
    here (out of scope for what was specified) -- this returns a
    ``{"results": [...]}`` shape with camelCased column names as a
    reasonable placeholder; adjust to match the real shape if/when needed.
    """
    results = [
        camelize(dict(zip(column_names, row)))
        for row in rows
    ]
    return {"results": results}
