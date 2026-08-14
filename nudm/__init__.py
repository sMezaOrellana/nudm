"""nudm: parse Google SecOps UDM search queries into an AST.

Primary entry point: :func:`nudm.parse`.
"""
from .nodes import (
    And,
    Assign,
    Comparison,
    Expr,
    FieldRef,
    FuncCall,
    Key,
    ListRef,
    Literal,
    MatchItem,
    Not,
    Or,
    OrderItem,
    Query,
    TimeGrain,
    VarRef,
)
from .duckdb_sql import UDMCompileError, compile_query
from .fake_data import load_events, load_reference_list
from .parser import UDMQueryError, parse
from .rule_nodes import EventCount, EventRef, Rule
from .rule_parser import UDMRuleError, parse_rule
from .rule_sql import compile_rule
from .schema import UDMSchema
from .search import run_rule, search

__all__ = [
    "parse",
    "UDMQueryError",
    "Query",
    "Expr",
    "FieldRef",
    "VarRef",
    "Literal",
    "ListRef",
    "FuncCall",
    "Comparison",
    "Not",
    "And",
    "Or",
    "Assign",
    "Key",
    "MatchItem",
    "TimeGrain",
    "OrderItem",
    "UDMSchema",
    "compile_query",
    "UDMCompileError",
    "load_events",
    "load_reference_list",
    "search",
    # YARA-L 2.0 rules (distinct path: rule name { meta: events: match:
    # outcome: condition: options: })
    "parse_rule",
    "compile_rule",
    "run_rule",
    "UDMRuleError",
    "Rule",
    "EventRef",
    "EventCount",
]
