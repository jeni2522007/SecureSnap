"""Evaluator for the SecureSnap forensic rule language.

Rules are matched against the *facts* produced by the analysis pipeline - a
nested dictionary of measurements. The evaluator never raises on a missing
field: an absent value simply makes the comparison false, so a rule written
for one evidence type does not crash when applied to another.
"""

import re

from .parser import (
    Comparison,
    ExistsOp,
    Literal,
    LogicalOp,
    Path,
    UnaryOp,
)


def resolve_path(facts, parts):
    """Walk a dotted path through the facts structure.

    Returns None when any step of the path is missing.
    """
    current = facts
    for part in parts:
        if isinstance(current, dict):
            if part not in current:
                return None
            current = current[part]
        elif isinstance(current, (list, tuple)):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


def _is_present(value):
    """A value counts as present when it is not None and not an empty string."""
    return value is not None and value != ""


def evaluate(node, facts):
    """Evaluate an AST node against the facts dictionary."""
    if isinstance(node, LogicalOp):
        left = evaluate(node.left, facts)
        if node.operator == "AND":
            # Short-circuit so that expensive checks are skipped.
            return bool(left) and bool(evaluate(node.right, facts))
        return bool(left) or bool(evaluate(node.right, facts))

    if isinstance(node, UnaryOp):
        return not evaluate(node.operand, facts)

    if isinstance(node, ExistsOp):
        return _is_present(resolve_path(facts, node.path.parts))

    if isinstance(node, Comparison):
        return _compare(node, facts)

    if isinstance(node, Literal):
        return bool(node.value)

    if isinstance(node, Path):
        return bool(resolve_path(facts, node.parts))

    return False


def _operand_value(node, facts):
    """Resolve one side of a comparison to a concrete value."""
    if isinstance(node, Literal):
        return node.value
    if isinstance(node, Path):
        return resolve_path(facts, node.parts)
    if isinstance(node, ExistsOp):
        return bool(evaluate(node, facts))
    if isinstance(node, UnaryOp):
        return bool(evaluate(node, facts))
    return None


def _compare(node, facts):
    """Evaluate a comparison between two operands."""
    left = _operand_value(node.left, facts)
    right = _operand_value(node.right, facts)

    operator = node.operator

    if operator == "TRUTHY":
        if isinstance(left, (list, tuple, dict, str)):
            return bool(len(left))
        return bool(left)

    if operator == "EXISTS":
        return _is_present(left)

    if operator in ("CONTAINS", "IN"):
        if left is None or right is None:
            return False
        if isinstance(left, str):
            return str(right) in left
        if isinstance(left, (list, tuple, set)):
            return right in left
        if isinstance(left, dict):
            return right in left
        return False

    if operator == "MATCHES":
        if left is None or right is None:
            return False
        try:
            return re.search(str(right), str(left)) is not None
        except re.error:
            return False

    if left is None or right is None:
        return False

    # Numeric comparison when both sides look numeric.
    if isinstance(left, bool) or isinstance(right, bool):
        left_value, right_value = bool(left), bool(right)
    elif isinstance(left, (int, float)) and isinstance(right, (int, float)):
        left_value, right_value = left, right
    else:
        left_value, right_value = str(left), str(right)

    try:
        if operator == "==":
            return left_value == right_value
        if operator == "!=":
            return left_value != right_value
        if operator == ">":
            return left_value > right_value
        if operator == ">=":
            return left_value >= right_value
        if operator == "<":
            return left_value < right_value
        if operator == "<=":
            return left_value <= right_value
    except TypeError:
        return False

    return False


def evaluate_rule(rule, facts):
    """Evaluate a parsed rule and return a result dictionary."""
    try:
        matched = evaluate(rule.condition, facts)
        error = None
    except Exception as exception:  # pragma: no cover - defensive
        matched = False
        error = str(exception)

    return {
        "name": rule.name,
        "action": rule.action,
        "severity": rule.severity,
        "description": rule.description,
        "condition": rule.condition.describe()
        if hasattr(rule.condition, "describe") else str(rule.condition),
        "matched": bool(matched),
        "error": error,
    }


def validate_rule(text):
    """Parse a condition and report whether it is valid, without running it."""
    from .parser import ParseError, parse_expression

    try:
        expression = parse_expression(text)
    except ParseError as error:
        return {
            "valid": False,
            "error": str(error),
        }

    return {
        "valid": True,
        "error": None,
        "parsed": {
            "condition": expression.describe(),
        },
    }
