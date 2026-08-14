"""PEG grammar (parsimonious syntax) for Google SecOps UDM search queries.

Covers the YARA-L search dialect documented in:
  - https://docs.cloud.google.com/chronicle/docs/investigation/udm-search
  - https://docs.cloud.google.com/chronicle/docs/investigation/udm-search-best-practices
  - https://docs.cloud.google.com/chronicle/docs/investigation/statistics-aggregations-in-udm-search

Notes on design decisions:

* ``_`` is optional trivia: whitespace and both comment forms
  (``// line`` and ``/* block */``).
* ``nl`` is trivia containing at least one newline. Newlines separate
  statements in the events section; two adjacent condition lines combine
  with an implicit AND (per the docs: "AND is assumed if you omit an
  operator between two conditions"). At the top level this implicit AND
  also applies across plain whitespace with no newline at all (``body_sep``
  falls back to a bare run of spaces/tabs) -- but only at the top level.
  Inside ``( ... )`` a parenthesized group is a single ``or_expr``, which
  has no such fallback, so two conditions grouped in parens *must* be
  joined with an explicit ``and``/``or`` even across a newline.
* Explicit ``and``/``or``/``not`` operate across newlines because their
  surrounding whitespace rule is ``_``.
* ``line = assign / or_expr``: ``$x = <field path | function call>`` is an
  assignment; every other comparison (e.g. ``$x = "ALLOW"``) is a
  condition. This mirrors YARA-L placeholder semantics.
* Section headers (``events:`` ``match:`` ``outcome:`` ``dedup:``
  ``order:`` ``limit:``) are keyword tokens; they cannot collide with UDM
  field paths because field paths never contain a bare ``:``.
"""

GRAMMAR = r"""
query        = _ events_sec? match_sec? outcome_sec? dedup_sec? order_sec? limit_sec? _

events_sec   = events_hdr? body
events_hdr   = ~r"events(?![A-Za-z0-9_])"i _ ":" _
body         = line (body_sep !section_hdr line)*
body_sep     = nl / ~r"[ \t\r]+"
line         = assign / or_expr
assign       = variable _ "=" _ assign_rhs
assign_rhs   = func_call / bare_path

# A section header keyword followed by ':' — used as a lookahead to stop a
# section's item list from swallowing the next section's header as if it
# were one more bare field/continuation (all these keywords are otherwise
# syntactically valid bare field names).
section_hdr  = ~r"(events|match|outcome|dedup|order|limit)(?![A-Za-z0-9_])"i _ ":"

match_sec    = _ ~r"match(?![A-Za-z0-9_])"i _ ":" _ match_list
match_list   = match_item (match_sep !section_hdr match_item)*
match_sep    = "," _ / nl
match_item   = match_expr time_grain?
match_expr   = variable / field_ref
time_grain   = _ grain_kw _ first_kw? grain_qty? grain_unit
grain_kw     = (~r"over(?![A-Za-z0-9_])"i _ ~r"every(?![A-Za-z0-9_])"i) / ~r"by(?![A-Za-z0-9_])"i
first_kw     = ~r"first(?![A-Za-z0-9_])"i _
grain_qty    = ~r"[0-9]+" _
grain_unit   = ~r"(minutes?|mins?|min|hours?|hrs?|hr|days?|weeks?|wks?|months?|mos?|mo|m|h|d|w)(?![A-Za-z0-9_])"i

outcome_sec  = _ ~r"outcome(?![A-Za-z0-9_])"i _ ":" _ outcome_list
outcome_list = outcome_item (outcome_sep !section_hdr outcome_item)*
outcome_sep  = "," _ / nl
outcome_item = variable _ "=" _ expr

dedup_sec    = _ ~r"dedup(?![A-Za-z0-9_])"i _ ":" _ ref_list
ref_list     = ref_item (ref_sep !section_hdr ref_item)*
ref_sep      = "," _ / nl
ref_item     = variable / field_ref

order_sec    = _ ~r"order(?![A-Za-z0-9_])"i _ ":" _ order_list
order_list   = order_item (order_sep !section_hdr order_item)*
order_sep    = "," _ / nl
order_item   = (variable / field_ref) (_ direction)?
direction    = ~r"(asc|desc)(?![A-Za-z0-9_])"i

limit_sec    = _ ~r"limit(?![A-Za-z0-9_])"i _ ":" _ ~r"[0-9]+"

or_expr      = and_expr (or_op and_expr)*
or_op        = _ ~r"or(?![A-Za-z0-9_])"i _
and_expr     = unary (and_op unary)*
and_op       = _ ~r"and(?![A-Za-z0-9_])"i _
unary        = not_op unary / "(" _ or_expr ")" / condition / field_ref
not_op       = ~r"not(?![A-Za-z0-9_])"i _
condition    = any_kw? lhs_expr _ op _ rhs_expr nocase_kw?
any_kw       = ~r"any(?![A-Za-z0-9_])"i _
nocase_kw    = _ ~r"nocase(?![A-Za-z0-9_])"i
op           = "<=" / ">=" / "!=" / "=" / "<" / ">" / ~r"in(?![A-Za-z0-9_])"i

lhs_expr     = func_call / variable / field_ref / literal
rhs_expr     = func_call / list_ref / variable / literal / field_ref
expr         = func_call / list_ref / variable / field_ref / literal

func_call    = func_name "(" _ arg_list? ")"
func_name    = ident ("." ident)*
arg_list     = expr ("," _ expr)*
list_ref     = "%" ident ("." ident)*
variable     = "$" ident !"."
field_ref    = dollar_prefixed / bare_path
dollar_prefixed = "$" ident "." bare_path
bare_path    = ident path_tail*
path_tail    = "." ident / index_or_key
index_or_key = "[" _ (string_lit / ~r"[0-9]+") _ "]"

literal      = template_var / string_lit / regex_lit / number / boolean / bareword
template_var = "${" ~r"[A-Za-z_][A-Za-z0-9_]*" "}"
string_lit   = "\"" ~r"(\\.|[^\"\\])*" "\""
regex_lit    = "/" ~r"(\\.|[^/\\])+" "/"
number       = ~r"-?[0-9]+(\.[0-9]+)?(?![A-Za-z0-9_.])"
boolean      = ~r"(true|false)(?![A-Za-z0-9_])"i
bareword     = ~r"[A-Za-z0-9_][A-Za-z0-9_.\-]*"

ident        = ~r"[A-Za-z_][A-Za-z0-9_]*"

_            = trivia*
nl           = (line_comment / block_comment / ~r"[ \t\r]")* "\n" trivia*
trivia       = line_comment / block_comment / ~r"\s"
line_comment = "//" ~r"[^\n]*"
block_comment= ~r"/\*(?s:.*?)\*/"
"""
