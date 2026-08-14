"""PEG grammar for full YARA-L 2.0 rules: ``rule name { meta: events:
match: outcome: condition: options: }``.

Reuses nearly all of :mod:`nudm.grammar`'s ``GRAMMAR`` text as-is (boolean
expressions, field paths, literals, ``match:``/``outcome:`` syntax,
comments) via textual composition -- a change to a rule shared between the
two dialects (e.g. ``literal``) automatically applies here too. Only new
surface:

* ``rule_file``: the ``rule name { ... }`` wrapper and section sequence
  (``meta, events, match, outcome, condition, options`` -- ``condition:``
  can reference outcome variables, so it's ordered after ``outcome:``).
* ``meta_sec`` / ``options_sec``: simple ``ident = literal`` key/value
  lists.
* ``condition_sec``: a boolean expression over ``$var`` (the event
  variable matched at least once), ``#var`` (count of matches) and
  outcome variables. Mirrors ``or_expr``/``and_expr``/``unary``'s shape
  but is kept as a separate parallel rule set (``cond_or_expr`` etc.)
  rather than widening the shared ``lhs_expr``/``rhs_expr``, so ``#count``
  syntax doesn't leak into the plain UDM query dialect. Deliberately
  narrower than a full condition: only ``event_count``/``variable``/
  ``literal`` are valid comparison operands here (field-level filtering
  belongs in ``events:``, not ``condition:``).
* ``rule_events_sec``: like ``events_sec`` but with a *mandatory* header
  (``events_hdr body`` instead of ``events_hdr? body``). A rule's
  ``events:`` header can't be made optional the way a bare search-bar
  query's can: ``body``'s first line has no ``!section_hdr`` guard, so an
  optional header here would let a headerless events section greedily
  swallow the next section's content as a bare field-existence line.
"""
from .grammar import GRAMMAR

RULE_ADDITIONS = r"""
rule_file       = _ ~r"rule(?![A-Za-z0-9_])"i _ ident _ "{" _ meta_sec? rule_events_sec? match_sec? outcome_sec? condition_sec options_sec? _ "}" _
rule_events_sec = _ events_hdr body

meta_sec      = _ ~r"meta(?![A-Za-z0-9_])"i _ ":" _ meta_list
meta_list     = meta_item (body_sep !section_hdr meta_item)*
meta_item     = ident _ "=" _ literal

condition_sec   = _ ~r"condition(?![A-Za-z0-9_])"i _ ":" _ cond_or_expr
cond_or_expr    = cond_and_expr (or_op cond_and_expr)*
cond_and_expr   = cond_unary (and_op cond_unary)*
# YARA-L condition: negation is written "!$var" (a bang), not the "not"
# keyword used in events:/search-bar boolean expressions -- accept both.
cond_unary      = cond_not_op cond_unary / "(" _ cond_or_expr ")" / cond_atom
cond_not_op     = "!" _ / not_op
cond_atom       = cond_comparison / event_count / variable
cond_comparison = cond_operand _ op _ cond_operand
cond_operand    = event_count / variable / literal
event_count     = "#" ident

options_sec   = _ ~r"options(?![A-Za-z0-9_])"i _ ":" _ options_list
options_list  = options_item (body_sep !section_hdr options_item)*
options_item  = ident _ "=" _ literal
"""

RULE_GRAMMAR = RULE_ADDITIONS + GRAMMAR
