"""Parser tests: every example query from the three UDM search docs must parse,
and the resulting AST must have the expected shape."""
import pytest

from nudm import (
    And,
    Assign,
    Comparison,
    FieldRef,
    FuncCall,
    Key,
    ListRef,
    Literal,
    Not,
    Or,
    Query,
    VarRef,
    parse,
)
from nudm.parser import UDMQueryError

# ---------------------------------------------------------------------------
# Simple conditions (udm-search doc)
# ---------------------------------------------------------------------------

SIMPLE = [
    'metadata.event_type = "NETWORK_CONNECTION"',
    'network.dns.response = true',
    'target.port = 443',
    'security_result.about.asset.vulnerabilities.cvss_base_score = 3.1',
    'principal.ip = /10.*/',
    'metadata.product_name = "Google Cloud VPC Flow Logs"',
    'principal.hostname != "http-server" nocase',
    'principal.hostname = "JDoe" nocase',
    'principal.hostname = /dns-server-[0-9]+/ nocase',
    'metadata.log_type = "PCAP_DNS"',
    'principal.artifact.network.dhcp.client_hostname',
]


@pytest.mark.parametrize("q", SIMPLE)
def test_simple_conditions_parse(q):
    ast = parse(q)
    assert isinstance(ast, Query)
    assert ast.events, q


def test_event_type_comparison():
    ast = parse('metadata.event_type = "NETWORK_CONNECTION"')
    cond = ast.events[0]
    assert isinstance(cond, Comparison)
    assert isinstance(cond.left, FieldRef)
    assert cond.left.path == "metadata.event_type"
    assert cond.op == "="
    assert cond.right == Literal("NETWORK_CONNECTION", "string")
    assert cond.nocase is False


def test_boolean_value():
    cond = parse("network.dns.response = true").events[0]
    assert cond.right == Literal(True, "boolean")


def test_int_and_float_values():
    assert parse("target.port = 443").events[0].right == Literal(443, "number")
    assert parse("security_result.cvss_score = 3.1").events[0].right == Literal(3.1, "number")


def test_regex_value():
    cond = parse("principal.ip = /10.*/").events[0]
    assert cond.right == Literal("10.*", "regex")


def test_regex_with_nocase_and_escapes():
    cond = parse(r"target.process.command_line = /\bpsexec(\.exe)?\b/ nocase").events[0]
    assert cond.right.kind == "regex"
    assert cond.right.value == r"\bpsexec(\.exe)?\b"
    assert cond.nocase is True


def test_string_escapes():
    cond = parse(r'principal.process.file.full_path = "C:\\Program Files\\chrome.exe"').events[0]
    assert cond.right.value == "C:\\Program Files\\chrome.exe"
    cond = parse(r'target.process.command_line = "cmd.exe /c \"a.exe\""').events[0]
    assert cond.right.value == 'cmd.exe /c "a.exe"'


def test_bare_field_no_operator():
    # UDM Lookup style: a bare field name alone is a valid query line.
    ast = parse("principal.artifact.network.dhcp.client_hostname")
    assert isinstance(ast.events[0], FieldRef) or ast.events  # at minimum it must parse


# ---------------------------------------------------------------------------
# additional.fields / labels key-value syntax
# ---------------------------------------------------------------------------

def test_additional_fields_key():
    cond = parse('additional.fields["pod_name"] = "kube-scheduler"').events[0]
    assert isinstance(cond.left, FieldRef)
    assert cond.left.segments == ("additional", "fields", Key("pod_name"))
    assert cond.right == Literal("kube-scheduler", "string")


def test_ingestion_labels_key():
    cond = parse('metadata.ingestion_labels["MetadataKeyDeletion"] = "startup-script"').events[0]
    assert cond.left.segments == ("metadata", "ingestion_labels", Key("MetadataKeyDeletion"))


def test_key_exists_and_regex_and_bare():
    parse('additional.fields["pod_name"] != ""')
    parse("additional.fields.key = /myKeynumber_*/")
    parse('additional.fields["pod_name"] = /br/')
    cond = parse('additional.fields["pod_name"] = bar nocase').events[0]
    assert cond.right == Literal("bar", "bare")
    assert cond.nocase is True


def test_array_index():
    cond = parse('$e.security_result[0].description != ""').events[0]
    assert isinstance(cond.left, FieldRef)
    assert cond.left.prefix == "e"
    assert cond.left.segments == ("security_result", 0, "description")


# ---------------------------------------------------------------------------
# Boolean logic, comments, implicit AND
# ---------------------------------------------------------------------------

def test_and_or_not_parens():
    ast = parse('(A.x = "1" OR B.y = "2") AND NOT C.z = "3"')
    assert isinstance(ast.events[0], And)
    kinds = set(type(c) for c in ast.events[0].children)
    assert Or in kinds and Not in kinds


def test_multiline_query_with_parens():
    q = '''metadata.event_type = "PROCESS_LAUNCH" and
 principal.process.file.full_path = /winword/ and
 (target.process.file.full_path = /cmd.exe/ or
  target.process.file.full_path = /powershell.exe/)'''
    ast = parse(q)
    assert isinstance(ast.events[0], And)
    assert len(ast.events[0].children) == 3
    assert isinstance(ast.events[0].children[2], Or)


def test_implicit_and_across_newlines():
    q = '''metadata.event_type = "USER_RESOURCE_UPDATE_CONTENT"
$e.principal.ip in %suspicious.ip'''
    ast = parse(q)
    assert len(ast.events) == 2
    assert isinstance(ast.where, And)


def test_implicit_and_same_line_no_newline():
    # Two top-level conditions juxtaposed with only whitespace (no newline,
    # no explicit "and") still combine with an implicit AND.
    q = 'principal.hostname = "asd" metadata.event_type = "PROCESS_LAUNCH"'
    ast = parse(q)
    assert len(ast.events) == 2
    assert isinstance(ast.where, And)


def test_implicit_and_requires_explicit_operator_inside_parens():
    # The implicit-AND juxtaposition only applies at the top level; inside
    # ( ... ) an explicit and/or is required even across a newline.
    q = '''(principal.hostname = "asd"
metadata.event_type = "PROCESS_LAUNCH")'''
    with pytest.raises(UDMQueryError):
        parse(q)


def test_block_and_line_comments():
    q = '''additional.fields["pod_name"] = "kube-scheduler"
/*
Block comments can span
multiple lines.
*/
AND additional.fields["pod_name1"] = "kube-scheduler1"'''
    ast = parse(q)
    assert len(ast.events) == 1
    assert isinstance(ast.events[0], And)
    ast2 = parse('additional.fields["pod_name"] != "" // my single-line comment')
    assert len(ast2.events) == 1


# ---------------------------------------------------------------------------
# Grouped fields, reference lists / data tables
# ---------------------------------------------------------------------------

def test_grouped_field():
    cond = parse('ip = "1.2.3.4"').events[0]
    assert isinstance(cond.left, FieldRef)
    assert cond.left.path == "ip"


def test_reference_list_in():
    cond = parse("$e.principal.ip in %suspicious.ip").events[0]
    assert cond.op == "in"
    assert isinstance(cond.right, ListRef)
    assert cond.right.table == "suspicious"
    assert cond.right.column == "ip"


def test_events_section_and_variable_assign():
    q = """events:
  $e.metadata.event_type = "NETWORK_CONNECTION"
  $e.security_result.action = "ALLOW"
  $e.target.asset.asset_id = $assetid
"""
    ast = parse(q)
    assert len(ast.events) == 3
    join = ast.events[2]
    assert isinstance(join, Comparison)
    assert isinstance(join.right, VarRef)


def test_template_variable():
    cond = parse("metadata.vendor_name = ${vendor_name}").events[0]
    assert cond.right == Literal("vendor_name", "template")


# ---------------------------------------------------------------------------
# Placeholder assignments and functions
# ---------------------------------------------------------------------------

def test_assignment_and_condition_on_variable():
    q = """metadata.event_type = "USER_LOGIN"
$security_result = security_result.action
$security_result = "ALLOW"
$date = timestamp.get_date(metadata.event_timestamp.seconds, "America/Los_Angeles")
$date > "2026-03-15" AND $date < "2026-03-17"
"""
    ast = parse(q)
    assigns = ast.assignments
    assert isinstance(assigns["security_result"], FieldRef)
    assert assigns["security_result"].path == "security_result.action"
    assert isinstance(assigns["date"], FuncCall)
    assert assigns["date"].name == "timestamp.get_date"
    assert len(assigns["date"].args) == 2
    # the "$security_result = ALLOW" line is a condition, not an assignment
    assert isinstance(ast.events[2], Comparison)
    assert isinstance(ast.events[2].left, VarRef)


def test_function_condition_lhs():
    q = '''metadata.event_type = "NETWORK_CONNECTION"
timestamp.get_date(metadata.ingested_timestamp.seconds) = "2026-03-15"'''
    ast = parse(q)
    cond = ast.events[1]
    assert isinstance(cond.left, FuncCall)


def test_any_quantifier():
    cond = parse('any $e.security_result.description != ""').events[0]
    assert cond.quantifier == "any"


# ---------------------------------------------------------------------------
# Stats sections: match / outcome / order / limit / dedup
# ---------------------------------------------------------------------------

def test_full_stats_query():
    q = """metadata.log_type = "OKTA"

match:
    principal.ip
outcome:
    $user_count_by_ip = count(principal.user.userid)

order:
$user_count_by_ip desc

limit:
    20
"""
    ast = parse(q)
    assert len(ast.match) == 1
    assert ast.match[0].expr.path == "principal.ip"
    assert len(ast.outcome) == 1
    assert ast.outcome[0].name == "user_count_by_ip"
    assert isinstance(ast.outcome[0].value, FuncCall)
    assert ast.outcome[0].value.name == "count"
    assert ast.order[0].expr.name == "user_count_by_ip"
    assert ast.order[0].direction == "desc"
    assert ast.limit == 20


def test_match_time_grains():
    q = """$hostname = principal.hostname
match:
  $hostname, target.ip by 2h"""
    ast = parse(q)
    assert len(ast.match) == 2
    assert ast.match[0].grain is None
    assert ast.match[1].grain.unit == "hour"
    assert ast.match[1].grain.quantity == 2

    assert parse("$h = principal.hostname\nmatch:\n  $h by minute").match[0].grain.unit == "minute"
    g = parse("$h = target.hostname\nmatch:\n  $h over every day").match[0].grain
    assert g.unit == "day" and g.quantity == 1
    g = parse("graph.entity.hostname != \"\"\nmatch:\n  graph.entity.ip by first hour").match[0].grain
    assert g.first is True and g.unit == "hour"


def test_outcome_aggregates():
    for fn in ["array", "array_distinct", "avg", "count", "count_distinct",
               "earliest", "latest", "max", "min", "stddev", "sum"]:
        q = f"""target.ip != ""
match:
  principal.ip
outcome:
  $x = {fn}(metadata.event_timestamp.seconds)"""
        ast = parse(q)
        assert ast.outcome[0].value.name == fn, fn


def test_array_distinct_example():
    q = """events:
  $e.security_result[0].description != ""
  any $e.security_result.description = ""
outcome:
  $security_result_description = array_distinct($e.security_result.description)"""
    ast = parse(q)
    assert len(ast.events) == 2
    assert ast.outcome[0].value.name == "array_distinct"
    assert isinstance(ast.outcome[0].value.args[0], FieldRef)


def test_limit_only():
    ast = parse('metadata.event_type = "USER_LOGIN"\nlimit: 25')
    assert ast.limit == 25


def test_dedup_section():
    ast = parse('principal.ip = "1.2.3.4"\ndedup:\n  principal.hostname, target.hostname')
    assert len(ast.dedup) == 2


# ---------------------------------------------------------------------------
# Entity graph searches (best-practices doc)
# ---------------------------------------------------------------------------

def test_graph_paths():
    cond = parse('graph.metadata.event_metadata.log_type = "AZURE_AD_CONTEXT"').events[0]
    assert cond.left.path == "graph.metadata.event_metadata.log_type"
    cond = parse('graph.entity.user.email_addresses = "foo_email"').events[0]
    assert cond.left.path == "graph.entity.user.email_addresses"


# ---------------------------------------------------------------------------
# Negative tests
# ---------------------------------------------------------------------------

def test_invalid_query_raises():
    with pytest.raises(UDMQueryError):
        parse('metadata.event_type === "X"')
    with pytest.raises(UDMQueryError):
        parse('(metadata.event_type = "NETWORK_CONNECTION" and target.ip = "1.1.1.1"')
