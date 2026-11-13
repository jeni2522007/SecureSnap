"""Parser for the SecureSnap forensic rule language.

The parser builds a small abstract syntax tree that the evaluator can walk.
Keeping the parse step separate from the evaluation step means a rule can be
validated (and shown to the user) before it is ever run against evidence.
"""

from .lexer import SEVERITIES, LexerError, tokenize


class ParseError(Exception):
    """Raised when rule text does not match the grammar."""


class Node:
    """Base class for AST nodes."""

    def describe(self):
        raise NotImplementedError


class Literal(Node):
    """A constant value."""

    def __init__(self, value):
        self.value = value

    def describe(self):
        return repr(self.value)


class Path(Node):
    """A dotted reference into the evidence facts, e.g. metadata.gps.latitude."""

    def __init__(self, parts):
        self.parts = parts

    def describe(self):
        return ".".join(self.parts)


class UnaryOp(Node):
    """NOT <expression>"""

    def __init__(self, operator, operand):
        self.operator = operator
        self.operand = operand

    def describe(self):
        return f"NOT {self.operand.describe()}"


class ExistsOp(Node):
    """<path> EXISTS"""

    def __init__(self, path):
        self.path = path

    def describe(self):
        return f"{self.path.describe()} EXISTS"


class Comparison(Node):
    """<operand> <operator> <operand>"""

    def __init__(self, operator, left, right):
        self.operator = operator
        self.left = left
        self.right = right

    def describe(self):
        return f"{self.left.describe()} {self.operator} {self.right.describe()}"


class LogicalOp(Node):
    """<left> AND|OR <right>"""

    def __init__(self, operator, left, right):
        self.operator = operator
        self.left = left
        self.right = right

    def describe(self):
        return f"({self.left.describe()} {self.operator} {self.right.describe()})"


class Rule:
    """A parsed rule: name, condition, action and severity."""

    def __init__(self, name, condition, action, severity="MEDIUM", description=""):
        self.name = name
        self.condition = condition
        self.action = action
        self.severity = severity
        self.description = description

    def describe(self):
        return (
            f"WHEN {self.condition.describe()} THEN {self.action} "
            f"[SEVERITY {self.severity}]"
        )


class Parser:
    """Recursive-descent parser for the rule grammar.

    grammar:
        rule       := "RULE" NAME "WHEN" expression "THEN" NAME ("SEVERITY" NAME)?
        expression := or_expr
        or_expr    := and_expr ("OR" and_expr)*
        and_expr   := unary ("AND" unary)*
        unary      := "NOT" unary | primary
        primary    := "(" expression ")" | comparison
        comparison := operand [ operator operand ]
    """

    def __init__(self, tokens):
        self.tokens = tokens
        self.index = 0

    # -- token helpers ----------------------------------------------------

    def current(self):
        return self.tokens[self.index]

    def peek(self, offset=1):
        position = min(self.index + offset, len(self.tokens) - 1)
        return self.tokens[position]

    def advance(self):
        token = self.tokens[self.index]
        if token.type != "EOF":
            self.index += 1
        return token

    def match(self, token_type, value=None):
        token = self.current()
        if token.type != token_type:
            return False
        if value is not None and token.value != value:
            return False
        return True

    def expect(self, token_type, value=None):
        if not self.match(token_type, value):
            token = self.current()
            expected = value or token_type
            raise ParseError(
                f"Expected {expected} but found {token.value!r} "
                f"at position {token.position}"
            )
        return self.advance()

    # -- grammar ----------------------------------------------------------

    def parse_rule(self, description=""):
        self.expect("RULE")
        name = self.expect("NAME").value
        self.expect("WHEN")
        condition = self.parse_expression()
        self.expect("THEN")
        action = self.expect("NAME").value

        severity = "MEDIUM"
        if self.match("SEVERITY"):
            self.advance()
            severity = self.expect("NAME").value.upper()
            if severity not in SEVERITIES:
                raise ParseError(
                    f"Unknown severity '{severity}'. "
                    f"Expected one of {', '.join(sorted(SEVERITIES))}."
                )

        if not self.match("EOF"):
            raise ParseError(
                f"Unexpected trailing input at position {self.current().position}"
            )

        return Rule(name, condition, action, severity, description)

    def parse_expression(self):
        return self.parse_or()

    def parse_or(self):
        left = self.parse_and()
        while self.match("OR"):
            self.advance()
            right = self.parse_and()
            left = LogicalOp("OR", left, right)
        return left

    def parse_and(self):
        left = self.parse_unary()
        while self.match("AND"):
            self.advance()
            right = self.parse_unary()
            left = LogicalOp("AND", left, right)
        return left

    def parse_unary(self):
        if self.match("NOT"):
            self.advance()
            return UnaryOp("NOT", self.parse_unary())
        return self.parse_primary()

    def parse_primary(self):
        if self.match("LPAREN"):
            self.advance()
            expression = self.parse_expression()
            self.expect("RPAREN")
            return expression

        return self.parse_comparison()

    def parse_comparison(self):
        left = self.parse_operand()

        if self.match("EXISTS"):
            self.advance()
            if not isinstance(left, Path):
                raise ParseError("EXISTS can only be applied to a field path")
            left = ExistsOp(left)

        operator = self._current_operator()
        if operator is None:
            if isinstance(left, ExistsOp):
                # A bare existence check needs no truthiness wrapper, which
                # keeps the description shown by the syntax checker clean.
                return left
            # A bare operand is treated as a truthiness test.
            return Comparison("TRUTHY", left, Literal(True))

        self.advance()

        right = self.parse_operand()

        return Comparison(operator, left, right)

    def _current_operator(self):
        token = self.current()
        if token.type == "OP":
            return token.value
        if token.type in ("CONTAINS", "MATCHES", "IN"):
            return token.value
        return None

    def parse_operand(self):
        token = self.current()

        if token.type == "NUMBER":
            self.advance()
            return Literal(token.value)

        if token.type == "STRING":
            self.advance()
            return Literal(token.value)

        if token.type == "TRUE":
            self.advance()
            return Literal(True)

        if token.type == "FALSE":
            self.advance()
            return Literal(False)

        if token.type == "NAME":
            self.advance()
            parts = [token.value]
            while self.match("DOT"):
                self.advance()
                parts.append(self.expect("NAME").value)
            return Path(parts)

        raise ParseError(
            f"Unexpected token {token.value!r} at position {token.position}"
        )


def parse_rule(text, description=""):
    """Parse a complete rule definition."""
    try:
        tokens = tokenize(text)
    except LexerError as error:
        raise ParseError(str(error)) from error

    return Parser(tokens).parse_rule(description)


def parse_expression(text):
    """Parse a standalone condition (used by the rule testing tool)."""
    try:
        tokens = tokenize(text)
    except LexerError as error:
        raise ParseError(str(error)) from error

    parser = Parser(tokens)
    expression = parser.parse_expression()

    if not parser.match("EOF"):
        raise ParseError(
            f"Unexpected trailing input at position {parser.current().position}"
        )

    return expression
