"""Lexer for the SecureSnap forensic rule language.

Rules are written in a small, explicit language so that a policy can be
audited and shown to a court:

    RULE MetadataAbsent
    WHEN metadata.available == false AND format.category == "image"
    THEN ESCALATE_UNVERIFIED_SOURCE
    SEVERITY HIGH

This module turns rule text into a token stream. The parser and evaluator
live in the sibling modules.
"""

import re

KEYWORDS = {
    "RULE", "WHEN", "THEN", "SEVERITY", "AND", "OR", "NOT",
    "TRUE", "FALSE", "EXISTS", "CONTAINS", "MATCHES", "IN",
}

SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

TOKEN_SPECIFICATION = [
    ("NUMBER", r"\d+\.\d+|\d+"),
    ("STRING", r'"(?:[^"\\]|\\.)*"'),
    ("NAME", r"[A-Za-z_][A-Za-z0-9_]*"),
    ("OP", r"==|!=|>=|<=|>|<"),
    ("LPAREN", r"\("),
    ("RPAREN", r"\)"),
    ("DOT", r"\."),
    ("COMMA", r","),
    ("COLON", r":"),
    ("WS", r"[ \t\r\n]+"),
    ("COMMENT", r"//[^\n]*"),
]

MASTER_PATTERN = re.compile(
    "|".join(f"(?P<{name}>{pattern})" for name, pattern in TOKEN_SPECIFICATION)
)


class LexerError(Exception):
    """Raised when rule text cannot be tokenised."""


class Token:
    """A single lexical token."""

    __slots__ = ("type", "value", "position")

    def __init__(self, token_type, value, position):
        self.type = token_type
        self.value = value
        self.position = position

    def __repr__(self):  # pragma: no cover - debugging aid
        return f"Token({self.type}, {self.value!r})"


def tokenize(text):
    """Convert rule text into a list of tokens."""
    tokens = []
    position = 0
    length = len(text)

    while position < length:
        match = MASTER_PATTERN.match(text, position)

        if not match:
            raise LexerError(
                f"Unexpected character {text[position]!r} at position {position}"
            )

        token_type = match.lastgroup
        value = match.group()
        position = match.end()

        if token_type in ("WS", "COMMENT"):
            continue

        if token_type == "NAME" and value.upper() in KEYWORDS:
            tokens.append(Token(value.upper(), value, match.start()))
            continue

        if token_type == "STRING":
            tokens.append(Token("STRING", _unescape(value[1:-1]), match.start()))
            continue

        if token_type == "NUMBER":
            number = float(value) if "." in value else int(value)
            tokens.append(Token("NUMBER", number, match.start()))
            continue

        tokens.append(Token(token_type, value, match.start()))

    tokens.append(Token("EOF", None, length))
    return tokens


def _unescape(value):
    """Resolve escape sequences inside a quoted string."""
    return (value.replace("\\n", "\n")
                 .replace("\\t", "\t")
                 .replace('\\"', '"')
                 .replace("\\\\", "\\"))
