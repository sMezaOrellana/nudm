"""Load fake UDM event data (and reference lists) into DuckDB for
:mod:`nudm.duckdb_sql`-compiled queries to run against.

Fake events are stored one-per-row as a ``JSON`` column, in the same shape
as the real API's ``events[].udm`` object and keyed by the same snake_case
canonical UDM paths the query language itself uses (see
:mod:`nudm.duckdb_sql` for why: it means field references compile to JSON
paths with zero case conversion). Camel-casing and timestamp formatting
only happen once, on the way *out*, in :mod:`nudm.response`.

Each fake event may be written either as a bare UDM object
(``{"metadata": {...}, ...}``) or in the real API's per-event envelope
(``{"name": "...", "udm": {...}}``) so real example payloads can be used
as fixtures directly (just re-key camelCase -> snake_case). ``name`` is
optional either way; the real API's exact resource-name encoding isn't
public, so a missing one gets a random placeholder rather than a guess at
that format.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Iterable

EVENTS_TABLE = "events"
REFERENCE_LISTS_TABLE = "reference_lists"


def _load_json(source: Any) -> Any:
    if isinstance(source, (dict, list)):
        return source
    if isinstance(source, Path):
        return json.loads(source.read_text())
    if isinstance(source, str):
        path = Path(source)
        if path.exists():
            return json.loads(path.read_text())
        return json.loads(source)  # raw JSON text
    raise TypeError(f"Cannot load events from {type(source).__name__}")


def _extract_events(data: Any) -> list[dict]:
    if isinstance(data, dict):
        events = data.get("events")
        if events is None:
            raise ValueError('Expected a top-level "events" key')
        return events
    if isinstance(data, list):
        return data
    raise ValueError("Expected a JSON object with an \"events\" array, or a bare array of events")


def _unwrap_event(event: dict) -> tuple[str, dict]:
    """Accept either ``{"name": ..., "udm": {...}}`` or a bare UDM dict.
    Returns ``(name, udm_dict)``, generating a placeholder name if absent.
    """
    if "udm" in event:
        name = event.get("name") or f"fake-{uuid.uuid4().hex}"
        return name, event["udm"]
    return f"fake-{uuid.uuid4().hex}", event


def load_events(conn, source: Any, table: str = EVENTS_TABLE) -> int:
    """Load fake events into ``table`` (``name VARCHAR, event JSON`` per
    row).

    ``source`` may be a file path (str/Path), raw JSON text, or an
    already-parsed ``{"events": [...]}`` dict / bare list of event dicts.
    Returns the number of events loaded.
    """
    events = _extract_events(_load_json(source))
    conn.execute(f'CREATE OR REPLACE TABLE "{table}" (name VARCHAR, event JSON)')
    if events:
        rows = [(name, json.dumps(udm)) for name, udm in (_unwrap_event(e) for e in events)]
        conn.executemany(f'INSERT INTO "{table}" VALUES (?, ?)', rows)
    return len(events)


def load_reference_list(
    conn, list_name: str, column_name: str, values: Iterable[Any],
    table: str = REFERENCE_LISTS_TABLE,
) -> None:
    """Load one column of a %reference_list / data table, used by the UDM
    ``in`` operator (``$e.principal.ip in %suspicious.ip``)."""
    conn.execute(
        f'CREATE TABLE IF NOT EXISTS "{table}" '
        "(list_name VARCHAR, column_name VARCHAR, value VARCHAR)"
    )
    conn.execute(
        f'DELETE FROM "{table}" WHERE list_name = ? AND column_name = ?',
        [list_name, column_name],
    )
    rows = [(list_name, column_name, str(v)) for v in values]
    if rows:
        conn.executemany(f'INSERT INTO "{table}" VALUES (?, ?, ?)', rows)
