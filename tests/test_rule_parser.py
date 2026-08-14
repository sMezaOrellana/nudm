"""Parser tests for full YARA-L 2.0 rules (rule name { meta: events:
match: outcome: condition: options: })."""
import pytest

from nudm.nodes import And, Assign, Comparison, FieldRef, Not, VarRef
from nudm.rule_nodes import EventCount, EventRef
from nudm.rule_parser import UDMRuleError, parse_rule


def test_rule_wrapper_and_meta():
    r = parse_rule('''
rule my_rule {
    meta:
        author = "sec-team"
        severity = "HIGH"
        threshold = 5

    events:
        $e.metadata.event_type = "USER_LOGIN"

    condition:
        $e
}
''')
    assert r.name == "my_rule"
    assert r.meta == {"author": "sec-team", "severity": "HIGH", "threshold": 5}


def test_placeholder_assign_both_directions_recognized():
    # "$placeholder = $evar.path" (Assign) ...
    r1 = parse_rule('''
rule r1 {
    events:
        $e.metadata.event_type = "USER_LOGIN"
        $user = $e.target.user.userid
    condition:
        $e
}
''')
    assigns = [e for e in r1.events if isinstance(e, Assign)]
    assert len(assigns) == 1
    assert assigns[0].name == "user"
    assert assigns[0].value == FieldRef(segments=("target", "user", "userid"), prefix="e")

    # ... and "$evar.path = $placeholder" (a plain Comparison) are both
    # valid placeholder-definition idioms; the compiler (not the parser)
    # normalizes them.
    r2 = parse_rule('''
rule r2 {
    events:
        $e.target.user.userid = $user
    condition:
        $e
}
''')
    assert isinstance(r2.events[0], Comparison)
    assert r2.events[0].left == FieldRef(segments=("target", "user", "userid"), prefix="e")
    assert r2.events[0].right == VarRef(name="user")


def test_condition_event_ref_and_count():
    r = parse_rule('''
rule r {
    events:
        $e.metadata.event_type = "USER_LOGIN"
    condition:
        $e and #e >= 5
}
''')
    assert isinstance(r.condition, And)
    assert r.condition.children[0] == EventRef(name="e")
    cmp = r.condition.children[1]
    assert isinstance(cmp, Comparison)
    assert cmp.left == EventCount(name="e")
    assert cmp.op == ">="


def test_condition_bang_negation():
    r = parse_rule('''
rule r {
    events:
        $login.metadata.event_type = "USER_LOGIN"
        $logout.metadata.event_type = "USER_LOGOUT"
    condition:
        $login and !$logout
}
''')
    assert isinstance(r.condition, And)
    neg = r.condition.children[1]
    assert isinstance(neg, Not)
    assert neg.child == EventRef(name="logout")


def test_condition_can_reference_outcome_variable():
    r = parse_rule('''
rule r {
    events:
        $e.metadata.event_type = "USER_LOGIN"
    outcome:
        $risk_score = count($e.metadata.id)
    condition:
        $e and $risk_score > 40
}
''')
    cmp = r.condition.children[1]
    assert cmp.left == VarRef(name="risk_score")


def test_match_pivot_window():
    r = parse_rule('''
rule r {
    events:
        $login.metadata.event_type = "USER_LOGIN"
        $alert.metadata.event_type = "ALERT"
    match:
        $userid over 5m after $login
    condition:
        $login and $alert
}
''')
    grain = r.match[0].grain
    assert grain.anchor == "after"
    assert grain.pivot == "login"
    assert grain.unit == "minute"
    assert grain.quantity == 5


def test_options_and_if_in_outcome():
    r = parse_rule('''
rule r {
    events:
        $e.metadata.event_type = "USER_LOGIN"
    outcome:
        $failed_count = count($e.metadata.id)
        $risk_score = if($failed_count > 20, 90, 50)
    condition:
        $e
    options:
        allow_zero_values = true
        suppression_window = 24h
}
''')
    assert r.options == {"allow_zero_values": True, "suppression_window": "24h"}
    assert r.outcome[1].name == "risk_score"


def test_missing_condition_section_raises():
    with pytest.raises(UDMRuleError):
        parse_rule('''
rule no_condition {
    events:
        $e.metadata.event_type = "USER_LOGIN"
}
''')


def test_invalid_syntax_raises():
    with pytest.raises(UDMRuleError):
        parse_rule("rule bad { events: $e.a === \"x\" condition: $e }")
