"""One-shot CLI for running a SecOps parser over raw logs::

    python -m nudm.logstash_cli -p parser.txt raw_logs.txt
    python -m nudm.logstash_cli -p parser.txt raw_logs.json | jq .
    cat raw_logs.txt | python -m nudm.logstash_cli -p parser.txt -

``raw_logs`` is either a plain text file (one raw log message per line) or
a JSON file with a list of strings / ``{"message": ..., ...}`` objects.
Output is a ``{"events": [...]}`` JSON document on stdout in the same
snake_case shape :func:`nudm.load_events` accepts, so the pipeline is::

    python -m nudm.logstash_cli -p parser.txt raw.txt > events.json
    python -m nudm.repl -e events.json

Errors go to stderr; exit status reflects success/failure.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .duckdb_sql import UDMCompileError
from .logstash_exec import UDMParserExecError, run_parser
from .logstash_parser import UDMParserError, parse_parser


def _load_raw_logs(source: str) -> list:
    text = sys.stdin.read() if source == "-" else Path(source).read_text(encoding="utf-8")
    stripped = text.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        data = json.loads(text)
        if isinstance(data, dict):
            data = data.get("logs", [data])
        return data
    return [line for line in text.splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Run a SecOps parser (filter { ... }) over raw logs."
    )
    ap.add_argument("-p", "--parser", required=True,
                    help="path to the parser file (use - for stdin)")
    ap.add_argument("logs", help="raw logs file (one per line, or JSON list; - for stdin)")
    ap.add_argument("--no-schema", action="store_true",
                    help="skip validating event.idm.read_only_udm.* targets against the UDM schema")
    args = ap.parse_args(argv)

    parser_text = sys.stdin.read() if args.parser == "-" else Path(args.parser).read_text(encoding="utf-8")
    try:
        parser = parse_parser(parser_text)
        raw_logs = _load_raw_logs(args.logs)
        events = run_parser(parser, raw_logs, schema=False if args.no_schema else None)
    except (UDMParserError, UDMParserExecError, UDMCompileError,
            json.JSONDecodeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"events": events}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
