"""PEG grammar (parsimonious syntax) for Google SecOps *parser* syntax, the
logstash-like ``filter { ... }`` language used by Chronicle parsers and code
snippets to map raw logs into UDM.

Reference: https://docs.cloud.google.com/chronicle/docs/reference/parser-syntax
The docs state the syntax is "similar to Logstash, but not identical."

Design notes:

* The whole program is one top-level ``filter { ... }`` block containing a
  sequence of *statements*: plugin calls, ``if``/``else`` conditionals, and
  ``for`` loops.
* A plugin call is ``name { arg => value ... }``. Argument values may be
  strings, numbers, booleans, arrays (``[ ... ]``) or hashes (``{ ... }``).
* Hash pairs accept both ``=>`` and ``:`` separators because the reference
  docs use ``:`` inside ``grok { match => { "message": "..." } }`` but
  ``=>`` elsewhere (e.g. ``mutate { replace => { "a" => "b" } }``).
* Conditionals use ``[field]`` bracket references and the operators
  ``== != < > <= >= =~ !~ in`` joined by ``and``/``or``/``!``.
* ``for`` loops iterate a token's array elements (``for item in arr`` /
  ``for index, item in arr``) or, with the trailing ``map`` keyword, a
  token's key/value pairs (``for key, value in obj map``).
* ``#`` starts a line comment (logstash convention).
"""

GRAMMAR = r"""
parser_file  = _ filter_block _
filter_block = ~r"filter(?![A-Za-z0-9_])" _ "{" _ stmt_list? _ "}"

# Parsimonious has no implicit whitespace between repetitions, so statement
# lists get an explicit "_" separator (each statement's own sub-lists do the
# same).
stmt_list    = statement (_ statement)*
statement    = if_stmt / for_stmt / plugin_call

plugin_call  = ident _ "{" _ arg_pair* _ "}"
arg_pair     = arg_name _ "=>" _ value _
arg_name     = ident

value        = array / hash / string / boolean / number / bareword
hash         = "{" _ hash_pair* _ "}"
hash_pair    = hash_key _ hash_sep _ value _
hash_key     = string / bareword
hash_sep     = "=>" / ":"
array        = "[" _ array_items? _ "]"
array_items  = value (_ "," _ value)*

if_stmt      = if_kw _ condition _ "{" _ stmt_list? _ "}" _ else_clause?
if_kw        = ~r"if(?![A-Za-z0-9_])"
else_clause  = else_kw _ (if_stmt / else_block)
else_kw      = ~r"else(?![A-Za-z0-9_])"
else_block   = "{" _ stmt_list? _ "}"

condition    = or_expr
or_expr      = and_expr (or_op and_expr)*
or_op        = _ ~r"or(?![A-Za-z0-9_])" _
and_expr     = not_expr (and_op not_expr)*
and_op       = _ ~r"and(?![A-Za-z0-9_])" _
not_expr     = bang not_expr / "(" _ condition _ ")" / comparison / field_ref
bang         = "!" _
comparison   = operand _ cmp_op _ operand
cmp_op       = "=~" / "!~" / "==" / "!=" / "<=" / ">=" / "<" / ">" / in_kw
in_kw        = ~r"in(?![A-Za-z0-9_])"
operand      = field_ref / string / number / boolean / array

for_stmt     = for_kw _ for_vars _ in_kw _ for_iter _ map_kw? _ "{" _ stmt_list? _ "}"
for_kw       = ~r"for(?![A-Za-z0-9_])"
map_kw       = ~r"map(?![A-Za-z0-9_])"
for_vars     = ident (_ "," _ ident)?
for_iter     = xml_iter / ident
xml_iter     = ~r"xml(?![A-Za-z0-9_])" _ "(" _ ident _ "," _ xpath _ ")"
xpath        = ~r"[^)\s]+"

field_ref    = ("[" _ field_key _ "]")+
field_key    = string / bareword

string       = dq_string / sq_string
dq_string    = "\"" ~r"(\\.|[^\"\\])*" "\""
sq_string    = "'" ~r"(\\.|[^'\\])*" "'"
boolean      = ~r"(true|false)(?![A-Za-z0-9_])"
number       = ~r"-?[0-9]+(\.[0-9]+)?"
bareword     = ~r"[A-Za-z_@][A-Za-z0-9_.@]*"
ident        = ~r"[A-Za-z_][A-Za-z0-9_]*"

_            = trivia*
trivia       = comment / ~r"\s"
comment      = "#" ~r"[^\n]*"
"""
