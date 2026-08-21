"""Grok support: the vendored Logstash v1.4.2 predefined pattern dictionary
(``grok_patterns.txt``, the exact set the parser syntax reference pins) plus
a compiler from grok pattern strings to Python regular expressions.

A grok pattern string mixes three things: predefined pattern references
(``%{IP:ips}`` or bare ``%{IP}``), named regex captures
(``(?P<token>...)``), and plain regex. References expand recursively --
inner references may carry their own labels (e.g. ``SYSLOGPROG`` contains
``%{PROG:program}``), and every label becomes a captured token.

Two RE2-isms from the pattern file need translating for Python's ``re``:
atomic groups ``(?>...)`` (rewritten as plain non-capturing groups; this
only changes pathological backtracking behavior) and the ``(?<name>...)``
capture spelling (rewritten to ``(?P<name>...)``, taking care not to touch
``(?<=`` / ``(?<!`` lookbehinds).
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

PATTERNS_FILE = Path(__file__).resolve().parent / "grok_patterns.txt"

_GROK_REF = re.compile(r"%\{([A-Za-z0-9_]+)(?::([A-Za-z0-9_]+))?\}")
# "(?<" that is not a lookbehind ("(?<=" / "(?<!")
_BARE_NAMED_GROUP = re.compile(r"\(\?<(?![=!])")


class GrokError(ValueError):
    """Raised when a grok pattern can't be compiled."""


@lru_cache(maxsize=1)
def load_patterns() -> dict[str, str]:
    """The predefined pattern dictionary (name -> pattern text)."""
    patterns: dict[str, str] = {}
    for line in PATTERNS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, body = line.partition(" ")
        patterns[name] = body.strip()
    return patterns


@lru_cache(maxsize=256)
def compile_grok(pattern: str) -> tuple[re.Pattern[str], tuple[str, ...]]:
    """Compile a grok pattern string into ``(regex, token names)`` where the
    token names are the capture labels in order of first appearance.

    Raises :class:`GrokError` for unknown pattern names or anything Python's
    ``re`` can't compile.
    """
    patterns = load_patterns()
    seen: set[str] = set()

    def expand(text: str) -> str:
        out: list[str] = []
        pos = 0
        for m in _GROK_REF.finditer(text):
            out.append(text[pos:m.start()])
            name, label = m.group(1), m.group(2)
            if name not in patterns:
                raise GrokError(f"unknown grok pattern %{name}")
            expanded = expand(patterns[name])
            if label and label not in seen:
                seen.add(label)
                out.append(f"(?P<{label}>{expanded})")
            else:
                # Unlabeled, or a duplicate label (Python forbids repeated
                # group names): keep the text but capture nothing new.
                out.append(f"(?:{expanded})")
            pos = m.end()
        out.append(text[pos:])
        return "".join(out)

    regex = expand(pattern)
    regex = _BARE_NAMED_GROUP.sub("(?P<", regex)
    regex = regex.replace("(?>", "(?:")
    try:
        compiled = re.compile(regex)
    except re.error as exc:  # noqa: TRY003
        raise GrokError(f"cannot compile grok pattern {pattern!r}: {exc}") from exc
    # Named tokens = every named capture group, whether it came from a
    # ``%{NAME:label}`` reference or an inline ``(?P<label>...)`` in the
    # pattern text. ``groupindex`` is ordered by group number.
    return compiled, tuple(compiled.groupindex)
