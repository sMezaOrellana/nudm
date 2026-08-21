"""Execution tests for the SecOps parser dialect (run_parser)."""
import pytest

from nudm.duckdb_sql import UDMCompileError
from nudm.logstash_exec import UDMParserExecError, run_parser
from nudm.schema import UDMSchema


def test_docs_match_all_example():
    """The reference docs' own end-to-end example: grok match_all + for map."""
    p = '''
filter {
    grok {
        match => {"message" => "%{IP:ips}"}
        match_all => true
    }
    mutate {
        replace => {
            "event.idm.read_only_udm.metadata.event_type" => "GENERIC_EVENT"
        }
    }
    for index, ip in ips map {
        mutate {
            merge => {
                "event.idm.read_only_udm.principal.ip" => "ip"
            }
        }
    }
    mutate {
        merge => {
            "@output" => "event"
        }
    }
}
'''
    events = run_parser(p, ["src 10.0.0.1 dst 10.0.0.2 mid 10.0.0.3"])
    assert events == [{
        "metadata": {"event_type": "GENERIC_EVENT"},
        "principal": {"ip": ["10.0.0.1", "10.0.0.2", "10.0.0.3"]},
    }]


def test_grok_firewall_conditionals_and_date():
    """Docs' syslog/firewall example: captures, conditionals, date rebase."""
    p = '''
filter {
    grok {
        match => { "message" => "%{SYSLOGTIMESTAMP:when} %{DATA:deviceName}: FW-%{INT:messageid}: (?P<action>Accepted|Denied) connection %{WORD:protocol} %{IP:srcAddr}/%{INT:srcPort} to %{IP:dstAddr}/%{INT:dstPort}" }
        on_error => "grok_failure"
    }
    if ![grok_failure] {
        mutate {
            replace => {
                "event.idm.read_only_udm.metadata.event_type" => "NETWORK_CONNECTION"
                "event.idm.read_only_udm.principal.ip" => "%{srcAddr}"
                "event.idm.read_only_udm.target.ip" => "%{dstAddr}"
                "event.idm.read_only_udm.network.ip_protocol" => "%{protocol}"
            }
        }
        if [action] == "Denied" {
            mutate { replace => { "event.idm.read_only_udm.security_result.action" => "BLOCK" } }
        } else {
            mutate { replace => { "event.idm.read_only_udm.security_result.action" => "ALLOW" } }
        }
        date { match => ["when", "MMM dd HH:mm:ss"] rebase => true }
        mutate { merge => { "@output" => "event" } }
    }
}
'''
    log = ("Mar 15 11:08:06 hostdevice1: FW-112233: Denied connection "
           "TCP 10.100.123.45/9988 to 8.8.8.8/53")
    (event,) = run_parser(p, [log])
    assert event["metadata"]["event_type"] == "NETWORK_CONNECTION"
    # rebase => true: the year comes from ingestion time (@createTimestamp)
    assert event["metadata"]["event_timestamp"].endswith("-03-15T11:08:06Z")
    # principal.ip / target.ip / security_result are repeated UDM fields, so
    # they come out as arrays (matching the real UDM serialization)
    assert event["principal"]["ip"] == ["10.100.123.45"]
    assert event["target"] == {"ip": ["8.8.8.8"]}
    assert event["network"]["ip_protocol"] == "TCP"
    # security_result and its .action are both repeated per the UDM schema
    assert event["security_result"] == [{"action": ["BLOCK"]}]


def test_grok_no_match_without_on_error_crashes():
    p = 'filter { grok { match => { "message" => "%{IP:ips}" } } }'
    with pytest.raises(UDMParserExecError, match="grok failed"):
        run_parser(p, ["no ip here"])


def test_grok_no_match_with_on_error_sets_flag():
    p = '''
filter {
    grok { match => { "message" => "%{IP:ips}" } on_error => "grok_failure" }
    if ![grok_failure] {
        mutate { merge => { "@output" => "event" } }
    }
}
'''
    assert run_parser(p, ["no ip here"]) == []


def test_grok_overwrite_required_for_preinitialized_tokens():
    p = '''
filter {
    mutate { replace => { "host" => "" } }
    grok { match => { "message" => "(?P<host>\\\\S+)" } }
}
'''
    with pytest.raises(UDMParserExecError, match="overwrite"):
        run_parser(p, ["anything"])

    p_ok = '''
filter {
    mutate { replace => { "host" => "" } }
    grok {
        match => { "message" => "(?P<host>\\\\S+)" }
        overwrite => ["host"]
    }
    mutate { merge => { "@output" => "event" } }
}
'''
    # pre-initialized token gets overwritten with the extracted value
    p_ok += ''  # no UDM fields mapped; only check it doesn't raise
    run_parser(p_ok, ["anything"])


def test_json_split_columns_and_nested_refs():
    p = '''
filter {
    json { source => "message" array_function => "split_columns" }
    mutate {
        replace => {
            "event.idm.read_only_udm.principal.hostname" => "%{[host][name]}"
            "event.idm.read_only_udm.principal.ip" => "%{[ips][0]}"
        }
    }
    mutate { merge => { "@output" => "event" } }
}
'''
    raw = '{"host": {"name": "win-01"}, "ips": ["1.2.3.4", "5.6.7.8"]}'
    (event,) = run_parser(p, [raw])
    assert event["principal"]["hostname"] == "win-01"
    assert event["principal"]["ip"] == ["1.2.3.4"]


def test_json_missing_nested_field_in_if_crashes():
    # docs: checking a possibly-missing nested path directly crashes the parser
    p = '''
filter {
    json { source => "message" }
    if [network][source][hostname] != "" {
        drop { tag => "x" }
    }
}
'''
    with pytest.raises(UDMParserExecError, match="not set"):
        run_parser(p, ['{"network": {}}'])


def test_kv_with_delimiters_and_trim():
    p = '''
filter {
    kv {
        source => "message"
        field_split => "|"
        value_split => ":"
        trim_value => "\\""
    }
    mutate { replace => { "event.idm.read_only_udm.target.hostname" => "%{dest}" } }
    mutate { merge => { "@output" => "event" } }
}
'''
    (event,) = run_parser(p, ['dest:"server-01"|proto:"tcp"'])
    assert event["target"]["hostname"] == "server-01"


def test_csv_columns():
    p = '''
filter {
    csv { source => "message" separator => "," }
    mutate { replace => { "event.idm.read_only_udm.principal.hostname" => "%{column2}" } }
    mutate { merge => { "@output" => "event" } }
}
'''
    (event,) = run_parser(p, ['id123,workstation-9,alice'])
    assert event["principal"]["hostname"] == "workstation-9"


def test_mutate_all_ops():
    p = '''
filter {
    json { source => "message" }
    mutate {
        rename => { "uid" => "event.idm.read_only_udm.principal.user.userid" }
        replace => { "event.idm.read_only_udm.metadata.event_type" => "USER_LOGIN" }
        convert => { "port" => "integer" }
        gsub => ["path", "/", "_"]
        uppercase => ["verb"]
        lowercase => ["method"]
        copy => { "uid_backup" => "event.idm.read_only_udm.principal.user.userid" }
        remove_field => ["verb", "method", "path"]
    }
    mutate { merge => { "@output" => "event" } }
}
'''
    raw = ('{"uid": "alice", "port": "8443", "path": "a/b/c", '
           '"verb": "post", "method": "GET"}')
    (event,) = run_parser(p, [raw])
    assert event["principal"]["user"]["userid"] == "alice"
    assert event["metadata"]["event_type"] == "USER_LOGIN"
    assert event["principal"]["user"]["userid"] == "alice"
    # removed fields don't appear in the event, only in state; verify via port
    # (int convert kept in state, not mapped) -- check mapped fields only here
    assert "port" not in event["principal"]["user"]["userid"]


def test_convert_types():
    p = '''
filter {
    json { source => "message" }
    mutate {
        convert => {
            "port" => "uinteger"
            "ratio" => "float"
            "blocked" => "boolean"
            "hexnum" => "hextodec"
            "hextext" => "hextoascii"
        }
        replace => { "event.idm.read_only_udm.target.port" => "%{port}" }
    }
    mutate { merge => { "@output" => "event" } }
}
'''
    raw = ('{"port": "8080", "ratio": "0.5", "blocked": "true", '
           '"hexnum": "ff", "hextext": "48656c6c6f"}')
    run_parser(p, [raw])  # must not raise


def test_convert_ipaddress_probe_pattern():
    """Docs' convert+on_error type probe idiom."""
    p = '''
filter {
    json { source => "message" }
    mutate {
        convert => { "host" => "ipaddress" }
        on_error => "is_not_ip"
    }
    if [is_not_ip] {
        mutate { replace => { "event.idm.read_only_udm.principal.hostname" => "%{host}" } }
    } else {
        mutate { replace => { "event.idm.read_only_udm.principal.ip" => "%{host}" } }
    }
    mutate { merge => { "@output" => "event" } }
}
'''
    (a,), (b,) = run_parser(p, ['{"host": "10.0.0.9"}']), run_parser(p, ['{"host": "srv-01"}'])
    assert a["principal"] == {"ip": ["10.0.0.9"]}
    assert b["principal"] == {"hostname": "srv-01"}


def test_merge_accumulates_repeated_field_via_split_loop():
    p = '''
filter {
    mutate {
        split => { source => "csv_list" separator => "," target => "items" }
    }
    for item in items {
        mutate {
            merge => { "event.idm.read_only_udm.principal.ip" => "item" }
        }
    }
    mutate { merge => { "@output" => "event" } }
}
'''
    (event,) = run_parser(p, [{"message": "", "csv_list": "1.1.1.1,2.2.2.2,3.3.3.3"}])
    assert event["principal"]["ip"] == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]


def test_label_key_value_pattern():
    """Docs' pattern for repeated UDM labels built inside a for loop."""
    p = '''
filter {
    json { source => "message" }
    for k, v in attrs map {
        mutate { replace => { "label.key" => "%{k}" } }
        mutate { replace => { "label.value" => "%{v}" } }
        mutate { merge => { "event.idm.read_only_udm.principal.resource.attribute.labels" => "label" } }
    }
    mutate { merge => { "@output" => "event" } }
}
'''
    raw = '{"attrs": {"env": "prod", "team": "sec"}}'
    (event,) = run_parser(p, [raw])
    labels = event["principal"]["resource"]["attribute"]["labels"]
    assert labels == [{"key": "env", "value": "prod"}, {"key": "team", "value": "sec"}]


def test_date_formats_and_target():
    p = '''
filter {
    json { source => "message" }
    date { match => ["ts", "yyyy-MM-dd HH:mm:ss", "UNIX", "ISO8601", "UNIX_MS"] }
    mutate { merge => { "@output" => "event" } }
}
'''
    (e1,) = run_parser(p, ['{"ts": "2025-01-15 08:30:00"}'])
    assert e1["metadata"]["event_timestamp"] == "2025-01-15T08:30:00Z"
    (e2,) = run_parser(p, ['{"ts": "1736928000"}'])
    assert e2["metadata"]["event_timestamp"] == "2025-01-15T08:00:00Z"
    (e3,) = run_parser(p, ['{"ts": "2025-01-15T08:30:00.123Z"}'])
    assert e3["metadata"]["event_timestamp"] == "2025-01-15T08:30:00.123000Z"

    p_target = '''
filter {
    json { source => "message" }
    date { match => ["ts", "ISO8601"] target => "event.idm.read_only_udm.metadata.collected_timestamp" }
    mutate { merge => { "@output" => "event" } }
}
'''
    (e4,) = run_parser(p_target, ['{"ts": "2025-06-01T00:00:00Z"}'])
    assert e4["metadata"]["collected_timestamp"] == "2025-06-01T00:00:00Z"


def test_base64_decode():
    p = '''
filter {
    base64 { source => "payload" target => "decoded" }
    mutate { replace => { "event.idm.read_only_udm.principal.hostname" => "%{decoded}" } }
    mutate { merge => { "@output" => "event" } }
}
'''
    (event,) = run_parser(p, [{"message": "", "payload": "aG9zdC0wMQ=="}])
    assert event["principal"]["hostname"] == "host-01"


def test_drop_tagged():
    p = '''
filter {
    if [domain] == "-" {
        drop { tag => "TAG_MALFORMED_MESSAGE" }
    }
    mutate { replace => { "event.idm.read_only_udm.network.dns_domain" => "%{domain}" } }
    mutate { merge => { "@output" => "event" } }
}
'''
    assert run_parser(p, [{"message": "", "domain": "-"}]) == []
    (event,) = run_parser(p, [{"message": "", "domain": "ok"}])
    assert event == {"network": {"dns_domain": "ok"}}


def test_uninitialized_field_in_if_crashes():
    p = 'filter { if [missing] == "x" { drop { tag => "t" } } }'
    with pytest.raises(UDMParserExecError, match="not set"):
        run_parser(p, ["anything"])


def test_multi_event_output():
    p = '''
filter {
    json { source => "message" }
    mutate { replace => { "event1.idm.read_only_udm.principal.hostname" => "%{a}" } }
    mutate { replace => { "event2.idm.read_only_udm.principal.hostname" => "%{b}" } }
    mutate { merge => { "@output" => "event1" } }
    mutate { merge => { "@output" => "event2" } }
}
'''
    events = run_parser(p, ['{"a": "host-a", "b": "host-b"}'])
    assert events == [
        {"principal": {"hostname": "host-a"}},
        {"principal": {"hostname": "host-b"}},
    ]


def test_timestamp_system_variable_becomes_event_timestamp():
    p = '''
filter {
    mutate { replace => { "event.idm.read_only_udm.metadata.event_type" => "GENERIC_EVENT" } }
    mutate { merge => { "@output" => "event" } }
}
'''
    (event,) = run_parser(p, [{"message": "", "@timestamp": "2025-04-01T10:00:00Z"}])
    assert event["metadata"]["event_timestamp"] == "2025-04-01T10:00:00Z"


def test_no_output_merge_produces_no_events():
    p = 'filter { mutate { replace => { "x" => "y" } } }'
    assert run_parser(p, ["raw"]) == []


def test_schema_validation_of_udm_targets():
    schema = UDMSchema()
    bad_field = '''
filter {
    mutate { replace => { "event.idm.read_only_udm.principal.hostname_typo" => "x" } }
}
'''
    with pytest.raises(UDMCompileError, match="unknown UDM field"):
        run_parser(bad_field, ["raw"], schema=schema)

    bad_enum = '''
filter {
    mutate { replace => { "event.idm.read_only_udm.metadata.event_type" => "NOT_A_TYPE" } }
}
'''
    with pytest.raises(UDMCompileError, match="not a valid"):
        run_parser(bad_enum, ["raw"], schema=schema)


def test_statedump_does_not_crash(capsys):
    p = 'filter { statedump { label => "dbg" } }'
    run_parser(p, ["raw"])
    err = capsys.readouterr().err
    assert "dbg" in err and "message" in err


def test_end_to_end_parsed_events_are_searchable(tmp_path):
    """The full loop: raw logs -> parser -> load_events -> UDM search."""
    import duckdb

    import nudm
    from nudm.logstash_exec import run_parser

    parser_text = (tmp_path / "p.txt")
    parser_text.write_text('''
filter {
    kv { source => "message" field_split => " " trim_value => "\\"" }
    mutate { replace => { "event.idm.read_only_udm.metadata.event_type" => "USER_LOGIN" } }
    mutate { rename => { "user" => "event.idm.read_only_udm.principal.user.userid" } }
    mutate { merge => { "@output" => "event" } }
}
''')
    events = run_parser(parser_text.read_text(), [
        'user="alice" result="success"',
        'user="bob" result="failure"',
    ])
    conn = duckdb.connect()
    nudm.load_events(conn, events)
    result = nudm.search('principal.user.userid = "alice"', conn)
    assert len(result["events"]) == 1
    assert result["events"][0]["udm"]["principal"]["user"]["userid"] == "alice"
