"""End-to-end tests: UDM query text -> DuckDB SQL -> executed against fake
event data -> reshaped into the real API's response JSON."""
from pathlib import Path

import duckdb
import pytest

import nudm
from nudm.duckdb_sql import UDMCompileError
from nudm.fake_data import load_events, load_reference_list

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def conn():
    c = duckdb.connect()
    load_events(c, FIXTURES / "events.json")
    load_reference_list(c, "suspicious", "ip", ["10.0.0.9", "10.0.0.99"])
    return c


def _hostnames(result):
    return {e["udm"]["principal"]["hostname"] for e in result["events"]}


def test_simple_equality(conn):
    result = nudm.search('metadata.event_type = "NETWORK_CONNECTION"', conn)
    assert len(result["events"]) == 2
    assert _hostnames(result) == {"win-server-01"}


def test_response_envelope_shape(conn):
    result = nudm.search('metadata.event_type = "USER_LOGIN"', conn)
    [event] = result["events"]
    assert isinstance(event["name"], str) and event["name"]
    assert event["udm"]["metadata"]["eventType"] == "USER_LOGIN"
    assert "event_type" not in event["udm"]["metadata"]
    assert "udm" not in event["udm"]  # not double-wrapped


def test_numeric_comparison(conn):
    result = nudm.search("target.port = 443", conn)
    assert len(result["events"]) == 2


def test_and_or_not(conn):
    r = nudm.search('metadata.event_type = "NETWORK_CONNECTION" and target.port = 443', conn)
    assert len(r["events"]) == 1
    r = nudm.search('metadata.event_type = "NETWORK_CONNECTION" or metadata.event_type = "USER_LOGIN"', conn)
    assert len(r["events"]) == 3
    r = nudm.search('not (metadata.event_type = "NETWORK_CONNECTION")', conn)
    assert len(r["events"]) == 1


def test_nocase(conn):
    r = nudm.search('principal.hostname = "WIN-SERVER-01" nocase', conn)
    assert len(r["events"]) == 2


def test_regex(conn):
    r = nudm.search('metadata.event_type = /NETWORK.*/', conn)
    assert len(r["events"]) == 2
    r = nudm.search('metadata.event_type != /NETWORK.*/', conn)
    assert len(r["events"]) == 1


def test_repeated_field_any_semantics(conn):
    # security_result is repeated: a bare comparison means "any element".
    r = nudm.search('security_result.action = "BLOCK"', conn)
    assert len(r["events"]) == 2


def test_array_index(conn):
    r = nudm.search('security_result[0].action = "ALLOW"', conn)
    assert len(r["events"]) == 2


def test_grouped_field(conn):
    r = nudm.search('ip = "10.0.0.5"', conn)
    assert len(r["events"]) == 2


def test_struct_map_key_access(conn):
    r = nudm.search('additional.fields["pod_name"] = "kube-scheduler"', conn)
    assert len(r["events"]) == 1


def test_label_list_key_value_lookup(conn):
    r = nudm.search('metadata.ingestion_labels["team"] = "sec"', conn)
    assert len(r["events"]) == 1
    r = nudm.search('metadata.ingestion_labels["team"] = "nope"', conn)
    assert len(r["events"]) == 0


def test_reference_list_in(conn):
    r = nudm.search("principal.ip in %suspicious.ip", conn)
    assert len(r["events"]) == 1
    assert _hostnames(r) == {"laptop-02"}


def test_dedup(conn):
    r = nudm.search('metadata.event_type != ""\ndedup:\n  principal.hostname', conn)
    assert len(r["events"]) == 2  # win-server-01, laptop-02


def test_order_and_limit(conn):
    r = nudm.search('metadata.event_type != ""\norder:\n  principal.hostname desc\nlimit: 2', conn)
    assert len(r["events"]) == 2
    hostnames = [e["udm"]["principal"]["hostname"] for e in r["events"]]
    assert hostnames == sorted(hostnames, reverse=True)


def test_match_outcome_aggregation(conn):
    q = """metadata.event_type = "NETWORK_CONNECTION"
match:
  principal.hostname
outcome:
  $cnt = count(metadata.event_type)
"""
    r = nudm.search(q, conn)
    assert r["results"] == [{"principalHostname": "win-server-01", "cnt": 2}]


def test_events_assign_used_in_match(conn):
    q = """$host = principal.hostname
metadata.event_type = "NETWORK_CONNECTION"
match:
  $host
outcome:
  $cnt = count(metadata.event_type)
order:
  $cnt desc
"""
    r = nudm.search(q, conn)
    assert r["results"] == [{"host": "win-server-01", "cnt": 2}]


def test_undefined_variable_raises(conn):
    with pytest.raises(UDMCompileError):
        nudm.search("$undefined = \"x\"\nmatch:\n  $nope", conn)


def test_unsupported_scalar_function_raises(conn):
    with pytest.raises(UDMCompileError):
        nudm.search('timestamp.get_date(metadata.event_timestamp.seconds) = "2026-03-15"', conn)
