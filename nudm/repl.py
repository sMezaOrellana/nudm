"""Interactive UDM search REPL, backed by DuckDB and fake event data.

Usage::

    python -m nudm.repl --events tests/fixtures/events.json
    udm> metadata.event_type = "NETWORK_CONNECTION"
    <blank line submits>
    {"events": [...]}

Results print as one compact JSON document per line on stdout, so they
pipe straight into ``jq``::

    python -m nudm.repl -e events.json -q 'target.port = 443' | jq .

Non-interactive one-shot mode: pass ``-q/--query``, or pipe a query in on
stdin (its exit status reflects success/failure, for scripting). Anything
diagnostic (errors, the ``.sql`` toggle, prompts) goes to stderr so it
never lands in the piped JSON.
"""
from __future__ import annotations

import argparse
import json
import sys

import duckdb

from .duckdb_sql import UDMCompileError, compile_query
from .fake_data import load_events, load_reference_list
from .parser import UDMQueryError, parse
from .response import build_event_response, build_result_response
from .schema import UDMSchema

PROMPT = "udm> "
CONT_PROMPT = "...> "

HELP = """\
Commands:
  .load <path>                        reload fake events from a JSON file
  .ref <list> <column> <v1,v2,...>    load a %reference_list.column
  .sql                                toggle printing compiled SQL to stderr
  .help                                this message
  .exit / .quit / Ctrl-D              leave

Enter a UDM query (blank line submits, queries may span multiple lines):
"""


def _run_query(conn: duckdb.DuckDBPyConnection, schema: UDMSchema, text: str, show_sql: bool) -> dict:
    query = parse(text)
    sql = compile_query(query, schema)
    if show_sql:
        print(sql, file=sys.stderr)
    cursor = conn.execute(sql)
    rows = cursor.fetchall()
    if query.match or query.outcome:
        return build_result_response(rows, [d[0] for d in cursor.description])
    return build_event_response(rows)


def _read_query(stream) -> str | None:
    """Read lines until a blank one (query submitted) or EOF (None)."""
    lines: list[str] = []
    prompt = PROMPT
    while True:
        if stream.isatty():
            print(prompt, end="", file=sys.stderr, flush=True)
        line = stream.readline()
        if line == "":  # EOF
            return None if not lines else "\n".join(lines)
        line = line.rstrip("\n")
        if line == "" and lines:
            return "\n".join(lines)
        if line == "":
            continue
        lines.append(line)
        prompt = CONT_PROMPT


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Interactive UDM search REPL over fake DuckDB data.")
    ap.add_argument("-e", "--events", help="path to a {\"events\": [...]} JSON fixture")
    ap.add_argument("-q", "--query", help="run a single query and exit (one-shot mode)")
    ap.add_argument("--sql", action="store_true", help="print compiled SQL to stderr before running")
    args = ap.parse_args(argv)

    conn = duckdb.connect()
    schema = UDMSchema()
    if args.events:
        n = load_events(conn, args.events)
        print(f"loaded {n} events from {args.events}", file=sys.stderr)
    else:
        conn.execute('CREATE TABLE events (name VARCHAR, event JSON)')
        print("no --events given; starting with 0 events (use .load in the REPL)", file=sys.stderr)

    show_sql = args.sql

    if args.query is not None:
        try:
            result = _run_query(conn, schema, args.query, show_sql)
        except (UDMQueryError, UDMCompileError, duckdb.Error) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(result))
        return 0

    if not sys.stdin.isatty():
        # Piped, non-interactive: treat the whole stdin as one query.
        text = sys.stdin.read().strip()
        if not text:
            return 0
        try:
            result = _run_query(conn, schema, text, show_sql)
        except (UDMQueryError, UDMCompileError, duckdb.Error) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(result))
        return 0

    print(HELP, file=sys.stderr)
    while True:
        text = _read_query(sys.stdin)
        if text is None:
            print(file=sys.stderr)
            return 0
        stripped = text.strip()
        if stripped in (".exit", ".quit"):
            return 0
        if stripped == ".help":
            print(HELP, file=sys.stderr)
            continue
        if stripped == ".sql":
            show_sql = not show_sql
            print(f"show_sql = {show_sql}", file=sys.stderr)
            continue
        if stripped.startswith(".load "):
            path = stripped[len(".load "):].strip()
            try:
                n = load_events(conn, path)
                print(f"loaded {n} events from {path}", file=sys.stderr)
            except Exception as exc:  # noqa: BLE001
                print(f"error: {exc}", file=sys.stderr)
            continue
        if stripped.startswith(".ref "):
            parts = stripped[len(".ref "):].split()
            if len(parts) != 3:
                print("usage: .ref <list> <column> <v1,v2,...>", file=sys.stderr)
                continue
            list_name, column, values = parts
            load_reference_list(conn, list_name, column, values.split(","))
            print(f"loaded {list_name}.{column} ({len(values.split(','))} values)", file=sys.stderr)
            continue
        if not stripped:
            continue
        try:
            result = _run_query(conn, schema, text, show_sql)
        except (UDMQueryError, UDMCompileError, duckdb.Error) as exc:
            print(f"error: {exc}", file=sys.stderr)
            continue
        print(json.dumps(result))


if __name__ == "__main__":
    raise SystemExit(main())
