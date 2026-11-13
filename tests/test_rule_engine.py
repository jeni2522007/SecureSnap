"""Tests for the rule language: lexer, parser and evaluator."""

import unittest

from fixtures import BACKEND_FOLDER  # noqa: F401  (adds backend to sys.path)

from modules.rule_engine.evaluator import evaluate, evaluate_rule, validate_rule
from modules.rule_engine.lexer import LexerError, tokenize
from modules.rule_engine.parser import ParseError, parse_expression, parse_rule


FACTS = {
    "metadata": {
        "available": False,
        "gps": {"latitude": None, "longitude": None},
        "software_mentions_editing": True,
        "timestamp_anomaly_count": 2,
    },
    "ela": {"hot_block_ratio": 0.18, "error_uniformity": 0.2},
    "format": {"category": "image", "name": "JPEG image"},
    "copy_move": {"detected": True, "regions_count": 3},
    "risk": {"score": 71.5},
}


class TestLexer(unittest.TestCase):

    def test_tokenises_a_simple_condition(self):
        tokens = tokenize('metadata.available == false')
        types = [token.type for token in tokens]
        self.assertIn("NAME", types)
        self.assertIn("OP", types)
        self.assertEqual(tokens[-1].type, "EOF")

    def test_keywords_are_normalised(self):
        tokens = tokenize("a AND b OR NOT c")
        self.assertEqual(tokens[1].type, "AND")
        self.assertEqual(tokens[3].type, "OR")
        self.assertEqual(tokens[4].type, "NOT")

    def test_strings_are_unquoted(self):
        tokens = tokenize('name == "hello world"')
        self.assertEqual(tokens[2].value, "hello world")

    def test_comments_are_ignored(self):
        tokens = tokenize("a == 1 // trailing note")
        self.assertEqual(len([t for t in tokens if t.type != "EOF"]), 3)

    def test_invalid_character_raises(self):
        with self.assertRaises(LexerError):
            tokenize("a == @@@")


class TestParser(unittest.TestCase):

    def test_parses_a_full_rule(self):
        rule = parse_rule(
            "RULE TestRule WHEN metadata.available == false "
            "THEN ESCALATE_SEVERITY SEVERITY HIGH"
        )
        self.assertEqual(rule.name, "TestRule")
        self.assertEqual(rule.action, "ESCALATE_SEVERITY")
        self.assertEqual(rule.severity, "HIGH")

    def test_requires_a_rule_keyword(self):
        with self.assertRaises(ParseError):
            parse_rule("metadata.available == false THEN ESCALATE")

    def test_rejects_unknown_severity(self):
        with self.assertRaises(ParseError):
            parse_rule("RULE X WHEN a == 1 THEN B SEVERITY CATASTROPHIC")

    def test_rejects_trailing_input(self):
        with self.assertRaises(ParseError):
            parse_rule("RULE X WHEN a == 1 THEN B extra tokens here")

    def test_operator_precedence_and_over_or(self):
        expression = parse_expression("a == 1 AND b == 2 OR c == 3")
        self.assertEqual(expression.operator, "OR")

    def test_parentheses_override_precedence(self):
        expression = parse_expression("(a == 1 AND b == 2) OR c == 3")
        self.assertEqual(expression.operator, "OR")
        self.assertEqual(expression.left.operator, "AND")

    def test_bare_exists_check_is_not_wrapped_in_a_truthiness_test(self):
        expression = parse_expression("metadata.gps.latitude EXISTS")
        self.assertEqual(expression.describe(), "metadata.gps.latitude EXISTS")


class TestEvaluator(unittest.TestCase):

    def test_simple_equality(self):
        expression = parse_expression('format.category == "image"')
        self.assertTrue(evaluate(expression, FACTS))

    def test_equality_against_false(self):
        expression = parse_expression("metadata.available == false")
        self.assertTrue(evaluate(expression, FACTS))

    def test_numeric_comparison(self):
        expression = parse_expression("ela.hot_block_ratio > 0.12")
        self.assertTrue(evaluate(expression, FACTS))

    def test_missing_field_is_false_not_an_error(self):
        expression = parse_expression("metadata.nonexistent.field == 1")
        self.assertFalse(evaluate(expression, FACTS))

    def test_not_operator(self):
        expression = parse_expression("NOT metadata.available")
        self.assertTrue(evaluate(expression, FACTS))

    def test_exists_on_a_present_path(self):
        expression = parse_expression("metadata.gps.latitude EXISTS")
        self.assertFalse(evaluate(expression, FACTS))

        populated = {
            "metadata": {"gps": {"latitude": 12.5}},
        }
        self.assertTrue(evaluate(expression, populated))

    def test_and_requires_both_sides(self):
        expression = parse_expression(
            "metadata.available == false AND ela.hot_block_ratio > 0.12"
        )
        self.assertTrue(evaluate(expression, FACTS))

        expression = parse_expression(
            "metadata.available == true AND ela.hot_block_ratio > 0.12"
        )
        self.assertFalse(evaluate(expression, FACTS))

    def test_or_requires_either_side(self):
        expression = parse_expression(
            "metadata.available == true OR ela.hot_block_ratio > 0.12"
        )
        self.assertTrue(evaluate(expression, FACTS))

    def test_contains_operator(self):
        expression = parse_expression('format.category CONTAINS "ima"')
        self.assertTrue(evaluate(expression, FACTS))

    def test_matches_operator(self):
        expression = parse_expression('format.name MATCHES "^JPEG"')
        self.assertTrue(evaluate(expression, FACTS))

    def test_evaluate_rule_reports_the_match(self):
        rule = parse_rule(
            "RULE HighRisk WHEN risk.score >= 60 THEN ESCALATE_SEVERITY"
        )
        result = evaluate_rule(rule, FACTS)
        self.assertTrue(result["matched"])
        self.assertEqual(result["action"], "ESCALATE_SEVERITY")


class TestValidation(unittest.TestCase):

    def test_valid_condition_is_accepted(self):
        outcome = validate_rule("metadata.available == false")
        self.assertTrue(outcome["valid"])
        self.assertIsNone(outcome["error"])

    def test_invalid_condition_is_rejected(self):
        outcome = validate_rule("metadata.available ==")
        self.assertFalse(outcome["valid"])
        self.assertIsNotNone(outcome["error"])

    def test_valid_condition_reports_a_readable_description(self):
        outcome = validate_rule("metadata.gps.latitude EXISTS")
        self.assertTrue(outcome["valid"])
        self.assertEqual(
            outcome["parsed"]["condition"], "metadata.gps.latitude EXISTS"
        )


if __name__ == "__main__":
    unittest.main()
