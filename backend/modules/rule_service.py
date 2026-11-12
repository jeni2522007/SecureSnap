"""Rule execution service.

Loads the active rule set from the database, evaluates each rule against the
facts produced by the analysis pipeline and returns the triggered rules.
"""

from modules.rule_engine.evaluator import evaluate_rule
from modules.rule_engine.parser import ParseError, parse_expression

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _value(row, key, default=None):
    """Read a field from a database row or a plain dictionary."""
    if row is None:
        return default
    try:
        value = row[key]
    except (KeyError, IndexError, TypeError):
        value = default
    return default if value is None else value


def load_rules(connection, enabled_only=True):
    """Load the rule set from the database."""
    query = "SELECT * FROM rules"
    if enabled_only:
        query += " WHERE enabled = 1"
    query += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 " \
             "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC, name"

    return connection.execute(query).fetchall()


def run_rules(rules, facts):
    """Evaluate rules against facts and return the triggered ones.

    A rule that cannot be parsed is reported as an error rather than being
    silently skipped, so a broken rule can never quietly reduce the rigour
    of an examination.
    """
    results = []
    errors = []

    for row in rules:
        condition = _value(row, "condition", "")
        name = _value(row, "name", "unnamed rule")
        action = _value(row, "action", "")
        severity = _value(row, "severity", "MEDIUM")
        description = _value(row, "description", "") or ""

        try:
            expression = parse_expression(condition)

            class _Rule:
                pass

            rule = _Rule()
            rule.name = name
            rule.condition = expression
            rule.action = action
            rule.severity = severity
            rule.description = description

            outcome = evaluate_rule(rule, facts)
            results.append(outcome)

        except ParseError as error:
            errors.append({
                "name": name,
                "condition": condition,
                "error": str(error),
            })

    triggered = [result for result in results if result["matched"]]
    triggered.sort(
        key=lambda result: -SEVERITY_RANK.get(result["severity"], 0)
    )

    return {
        "evaluated": len(results),
        "triggered": triggered,
        "all_results": results,
        "errors": errors,
        "triggered_count": len(triggered),
    }


def summarise(triggered):
    """Summarise the triggered rules for display."""
    by_severity = {}
    actions = []

    for result in triggered:
        by_severity[result["severity"]] = by_severity.get(result["severity"], 0) + 1
        if result["action"] not in actions:
            actions.append(result["action"])

    return {
        "count": len(triggered),
        "by_severity": by_severity,
        "actions": actions,
    }
