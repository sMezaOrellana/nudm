# nudm

`nudm` parses Google SecOps UDM search queries and full YARA-L 2.0 rules,
compiles them to DuckDB SQL, and runs them against local fake event data.
It's a local testbed: write and sanity-check queries/rules without a real
Chronicle/SecOps backend.

Two independent dialects are supported, each with its own parser and
compiler:

1. **UDM search queries** -- the syntax typed into the SecOps search bar
   (`events:`/`match:`/`outcome:`/`dedup:`/`order:`/`limit:`, a single
   implicit event stream).
2. **YARA-L 2.0 rules** -- `rule name { meta: events: match: outcome:
   condition: options: }`, whose defining feature is multi-event
   correlation: several event variables (`$e1`, `$e2`, ...) joined on
   shared placeholder values.

## Install

Requires Python 3.13+.

```
uv sync            # or: pip install -e .
```

## Quick start

```python
import duckdb
import nudm

# 1) UDM search query
conn = duckdb.connect()
nudm.load_events(conn, "tests/fixtures/events.json")
result = nudm.search('principal.hostname = "win-server-01"', conn)
print(result)  # {"events": [...]}

# 2) YARA-L 2.0 rule (rule_events.json has enough repeated failed logins
# for "alice" within a 10-minute window to trip the >=5 threshold below)
conn = duckdb.connect()
nudm.load_events(conn, "tests/fixtures/rule_events.json")
result = nudm.run_rule('''
rule brute_force_login {
    events:
        $e.metadata.event_type = "USER_LOGIN"
        $e.security_result.action = "BLOCK"
        $user = $e.target.user.userid
    match:
        $user over 10m
    outcome:
        $failed_count = count($e.metadata.id)
    condition:
        #e >= 5
}
''', conn)
print(result)  # {"results": [{"user": "alice", "failedCount": 6}]}
```

`nudm.load_events` accepts a file path, raw JSON text, or an already-parsed
`{"events": [...]}` dict / bare list -- see `nudm/fake_data.py`. Events are
keyed by the same snake_case canonical UDM paths the query language uses
(`principal.hostname`, not `principal.hostName`); camelCase conversion
happens once, on the way out, to match the real API's response shape.

For the `in` operator / `%reference_list`, load a reference list first:

```python
conn = duckdb.connect()
nudm.load_events(conn, "tests/fixtures/events.json")
nudm.load_reference_list(conn, "suspicious", "ip", ["10.0.0.9", "10.0.0.99"])
nudm.search('principal.ip in %suspicious.ip', conn)  # matches "laptop-02"
```

### Lower-level API

Each dialect exposes parse / compile / run as separate steps if you want
the AST or the generated SQL directly:

```python
# UDM queries
query = nudm.parse('metadata.event_type = "NETWORK_CONNECTION"')
sql = nudm.compile_query(query, nudm.UDMSchema())

# YARA-L rules
rule = nudm.parse_rule(rule_text)
sql = nudm.compile_rule(rule, nudm.UDMSchema())
```

`UDMQueryError`/`UDMRuleError` are raised on malformed syntax;
`UDMCompileError` is raised for anything that parses but can't be
compiled (an unknown field, an invalid enum value, an unsupported
function, ...).

## REPL

```
python -m nudm.repl --events tests/fixtures/events.json
udm> metadata.event_type = "NETWORK_CONNECTION"
<blank line submits>
{"events": [...]}
```

One-shot mode (also usable in scripts/pipes -- exit status reflects
success/failure):

```
python -m nudm.repl -e tests/fixtures/events.json -q 'target.port = 443' | jq .
```

In-REPL commands: `.load <path>` (reload events), `.ref <list> <column>
<v1,v2,...>` (load a reference list), `.sql` (toggle printing compiled SQL
to stderr), `.help`, `.exit`. The REPL only runs UDM queries, not rules
(there is no `.rule` command yet -- use the Python API for rules).

## Schema-aware compilation

`udm_fields.csv` (the real UDM field dictionary) and `udm_enums.json` (real
enum member lists) are loaded by `nudm.UDMSchema` and used at compile time
to reject queries/rules referencing a field that doesn't exist, or
comparing an enum-typed field against a value that isn't one of its real
members -- both raise `UDMCompileError` rather than silently compiling to
a query that matches nothing.

## YARA-L rule support: what's covered

- `meta:`, `events:` (including placeholder assignment in either
  `$ph = $e.field` or `$e.field = $ph` form), `match:` (including a plain
  `over N<unit>` tumbling window and a pivot-relative `over N<unit>
  before/after $var` window), `outcome:` (aggregate functions plus
  `if(cond, a, b)`), `condition:` (`$var`, `#var`, `!$var`, and/or/not,
  comparisons against outcome variables), `options:` (parsed; only
  `suppression_window` is actively rejected, see below).
- Multi-event correlation: any number of event variables joined on shared
  placeholders, including `!$var` negation as either a correlated
  anti-join or (when `$var` shares no placeholder with anything else) a
  standalone existence check.

Known, deliberate limitations:

- **`graph.*`/entity fields are not supported** -- there's no entity data
  table to join against yet, only `events`. Raises `UDMCompileError`.
- **`options: suppression_window` is not supported** -- it requires
  persistent state across rule runs, which this stateless
  compile-one-query-and-run engine has nowhere to keep. Raises
  `UDMCompileError`.
- **`over N<unit>` is a tumbling window**, not a continuous sliding one:
  events are bucketed by `floor(epoch(ts) / window_seconds)`, so two
  events 1 second apart but straddling a bucket boundary won't correlate.
- **A `before`/`after $pivot` window requires the pivot to be the first
  event variable declared in `events:`.**
- Most scalar YARA-L functions (`re.regex()`, `net.ip_in_range_cidr()`,
  `strings.concat()`, ...) aren't implemented and raise `UDMCompileError`
  naming the function; the common regex case is covered by the `/pattern/`
  literal syntax instead. `if()` is the one function implemented in
  `outcome:` beyond the plain aggregates.

## Tests

```
uv run pytest
```

## Layout

- `nudm/grammar.py` / `nudm/parser.py` / `nudm/nodes.py` -- UDM query PEG
  grammar, parser, AST.
- `nudm/duckdb_sql.py` -- UDM query AST -> DuckDB SQL.
- `nudm/rule_grammar.py` / `nudm/rule_parser.py` / `nudm/rule_nodes.py` --
  YARA-L rule grammar (built by composing the UDM grammar with a small set
  of rule-specific additions), parser, AST.
- `nudm/rule_sql.py` -- rule AST -> DuckDB SQL (event-variable
  partitioning, join-graph construction, `condition:` -> `HAVING`).
- `nudm/schema.py` -- `udm_fields.csv`/`udm_enums.json` loader, field
  type/enum/repeated lookups, grouped-field expansion.
- `nudm/fake_data.py` -- loads fixture events/reference lists into DuckDB.
- `nudm/response.py` -- reshapes SQL results into the real API's response
  JSON (snake_case -> camelCase).
- `nudm/search.py` -- top-level `search()`/`run_rule()` convenience
  functions.
- `nudm/repl.py` -- interactive/piped CLI.
