"""End-to-end tests: YARA-L 2.0 rule text -> DuckDB SQL -> executed
against fake event data -> reshaped result, covering multi-event
correlation (the feature that doesn't exist in the plain UDM query path)."""
from pathlib import Path

import duckdb
import pytest

import nudm
from nudm.duckdb_sql import UDMCompileError

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def conn():
    c = duckdb.connect()
    nudm.load_events(c, FIXTURES / "rule_events.json")
    return c


def _by(result, key):
    return {row[key]: row for row in result["results"]}


def test_single_event_threshold_rule(conn):
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
    rows = _by(result, "user")
    assert set(rows) == {"alice"}
    assert rows["alice"]["failedCount"] == 6


def test_if_in_outcome(conn):
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
        $risk_score = if($failed_count > 20, 90, 50)
    condition:
        #e >= 5 and $risk_score > 40
}
''', conn)
    rows = _by(result, "user")
    assert rows["alice"]["riskScore"] == 50


def test_multi_event_placeholder_join(conn):
    result = nudm.run_rule('''
rule login_then_download {
    events:
        $login.metadata.event_type = "USER_LOGIN"
        $download.metadata.event_type = "FILE_CREATION"
        $login.principal.user.userid = $userid
        $download.principal.user.userid = $userid
    match:
        $userid over 10m
    condition:
        $login and $download
}
''', conn)
    assert {row["userid"] for row in result["results"]} == {"carol"}


def test_negation_correlated_anti_join(conn):
    result = nudm.run_rule('''
rule no_logout_after_login {
    events:
        $login.metadata.event_type = "USER_LOGIN"
        $logout.metadata.event_type = "USER_LOGOUT"
        $login.target.user.userid = $userid
        $logout.target.user.userid = $userid
    match:
        $userid
    condition:
        $login and !$logout
}
''', conn)
    assert {"alice", "bob", "dave"} <= {row["userid"] for row in result["results"]}


def test_negation_global_not_exists(conn):
    # $logout shares no placeholder with $login here, so "!$logout" must
    # compile to a standalone NOT EXISTS gate rather than a join.
    result = nudm.run_rule('''
rule no_logout_at_all {
    events:
        $login.metadata.event_type = "USER_LOGIN"
        $logout.metadata.event_type = "USER_LOGOUT"
    condition:
        $login and !$logout
}
''', conn)
    assert result["results"][0]["matches"] > 0


def test_pivot_window_after(conn):
    result = nudm.run_rule('''
rule pivot_window {
    events:
        $login.metadata.event_type = "USER_LOGIN"
        $login.principal.user.userid = $userid
        $download.metadata.event_type = "FILE_CREATION"
        $download.principal.user.userid = $userid
    match:
        $userid over 5m after $login
    condition:
        $login and $download
}
''', conn)
    assert {row["userid"] for row in result["results"]} == {"carol"}


def test_positive_evar_with_no_shared_placeholder_raises(conn):
    with pytest.raises(UDMCompileError):
        nudm.run_rule('''
rule bad {
    events:
        $a.metadata.event_type = "USER_LOGIN"
        $b.metadata.event_type = "USER_LOGOUT"
    condition:
        $a and $b
}
''', conn)


def test_graph_fields_rejected(conn):
    with pytest.raises(UDMCompileError):
        nudm.run_rule('''
rule uses_graph {
    events:
        $e.graph.entity.hostname = "x"
    condition:
        $e
}
''', conn)


def test_suppression_window_rejected(conn):
    with pytest.raises(UDMCompileError):
        nudm.run_rule('''
rule uses_suppression {
    events:
        $e.metadata.event_type = "USER_LOGIN"
    condition:
        $e
    options:
        suppression_window = 24h
}
''', conn)
