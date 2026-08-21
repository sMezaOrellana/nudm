"""Parser tests for the SecOps parser dialect (filter { ... })."""
import pytest

from nudm.logstash_nodes import (
    And,
    ArrayLit,
    Comparison,
    FieldRef,
    ForStmt,
    IfStmt,
    Literal,
    Not,
    PluginCall,
)
from nudm.logstash_parser import UDMParserError, parse_parser


def test_single_plugin_with_hash_and_bool_args():
    p = parse_parser('''
filter {
    grok {
        match => { "message" => "%{IP:ips}" }
        match_all => true
    }
}
''')
    (stmt,) = p.statements
    assert isinstance(stmt, PluginCall)
    assert stmt.name == "grok"
    assert stmt.args["match"] == {"message": "%{IP:ips}"}
    assert stmt.args["match_all"] is True


def test_hash_pairs_accept_both_arrow_and_colon():
    # the docs use both "=>" and ":" as hash separators
    p = parse_parser('''
filter {
    grok {
        match => {"message": "%{IP:ips}"}
    }
    mutate {
        replace => { "a" => "b" }
    }
}
''')
    assert p.statements[0].args["match"] == {"message": "%{IP:ips}"}
    assert p.statements[1].args["replace"] == {"a": "b"}


def test_multiple_statements_and_comments():
    p = parse_parser('''
filter {
    # extract
    json { source => "message" }
    # map
    mutate { replace => { "a" => "b" } }
}
''')
    assert [s.name for s in p.statements] == ["json", "mutate"]


def test_string_escapes_and_single_quotes():
    p = parse_parser('''
filter {
    mutate { replace => { "a" => "he said \\"hi\\"" "b" => 'it\\'s' "c" => "\\\\s" } }
}
''')
    (stmt,) = p.statements
    assert stmt.args["replace"]["a"] == 'he said "hi"'
    assert stmt.args["replace"]["b"] == "it's"
    # double backslash stays a single backslash (regex escape)
    assert stmt.args["replace"]["c"] == "\\s"


def test_array_values_preserve_order():
    p = parse_parser('filter { date { match => ["ts", "yyyy-MM-dd HH:mm:ss", "UNIX"] } }')
    assert p.statements[0].args["match"] == ["ts", "yyyy-MM-dd HH:mm:ss", "UNIX"]


def test_if_else_if_else_chain():
    p = parse_parser('''
filter {
    if [action] == "drop" {
        drop { tag => "T1" }
    } else if [action] == "allow" {
        drop { tag => "T2" }
    } else {
        drop { tag => "T3" }
    }
}
''')
    (stmt,) = p.statements
    assert isinstance(stmt, IfStmt)
    assert isinstance(stmt.cond, Comparison)
    assert stmt.cond.left == FieldRef(segments=("action",))
    assert stmt.cond.op == "=="
    assert stmt.cond.right == Literal("drop")
    assert stmt.then_body[0].name == "drop"
    # else-if chain: else_body holds a single nested IfStmt
    assert stmt.else_body is not None and len(stmt.else_body) == 1
    nested = stmt.else_body[0]
    assert isinstance(nested, IfStmt)
    assert nested.else_body[0].args["tag"] == "T3"


def test_condition_operators_and_bang():
    p = parse_parser('''
filter {
    if ![flag] { drop { tag => "x" } }
    if [a] =~ "^.+@.+$" { drop { tag => "y" } }
    if [proto] in ["tcp", "udp"] { drop { tag => "z" } }
    if [n] >= 3 and [m] != 2 { drop { tag => "w" } }
}
''')
    bang, regex, in_op, and_op = p.statements
    assert isinstance(bang.cond, Not)
    assert bang.cond.child == FieldRef(segments=("flag",))
    assert regex.cond.op == "=~"
    assert in_op.cond.op == "in"
    assert in_op.cond.right == ArrayLit(("tcp", "udp"))
    assert isinstance(and_op.cond, And)
    assert and_op.cond.children[0].op == ">="


def test_nested_field_refs_and_parens():
    p = parse_parser('filter { if ([network][src][hostname] != "") { drop { tag => "t" } } }')
    cond = p.statements[0].cond
    assert cond.left == FieldRef(segments=("network", "src", "hostname"))


def test_for_loop_forms():
    p = parse_parser('''
filter {
    for phone in phones { drop { tag => "t" } }
    for index, ip in ips map { drop { tag => "t" } }
}
''')
    first, second = p.statements
    assert isinstance(first, ForStmt)
    assert first.loop_vars == ("phone",)
    assert first.iterable == "phones"
    assert not first.is_map
    assert second.loop_vars == ("index", "ip")
    assert second.is_map
    assert len(second.body) == 1


def test_unknown_plugin_rejected():
    with pytest.raises(UDMParserError, match="unknown filter plugin"):
        parse_parser("filter { teleport { a => 1 } }")


def test_unknown_mutate_op_rejected():
    with pytest.raises(UDMParserError, match="unknown mutate operation"):
        parse_parser('filter { mutate { frobnicate => { "a" => "b" } } }')


def test_xml_plugin_rejected():
    with pytest.raises(UDMParserError, match="xml"):
        parse_parser('filter { xml { source => "message" xpath => { "/a" => "b" } } }')


def test_xml_for_loop_rejected():
    with pytest.raises(UDMParserError, match="xml"):
        parse_parser("filter { for i, _ in xml(message,/a/b) { drop { tag => \"t\" } } }")


def test_syntax_error_reports_line_column():
    with pytest.raises(UDMParserError, match=r"line 2, column"):
        parse_parser("filter {\n  grok {\n")
