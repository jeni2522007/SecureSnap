
import unittest

from backend.modules.rule_compiler import execute_rule


class TestRuleCompiler(unittest.TestCase):

    def test_flag_large_image(self):
        result = execute_rule(
            "IF image_size > 5000000 THEN FLAG_IMAGE",
            6000000
        )
        self.assertEqual(result, "FLAG_IMAGE")

    def test_allow_small_image(self):
        result = execute_rule(
            "IF image_size > 5000000 THEN FLAG_IMAGE",
            2000000
        )
        self.assertEqual(result, "ALLOW_IMAGE")

    def test_allow_exact_threshold(self):
        result = execute_rule(
            "IF image_size > 5000000 THEN FLAG_IMAGE",
            5000000
        )
        self.assertEqual(result, "ALLOW_IMAGE")

    def test_greater_than_or_equal(self):
        result = execute_rule(
            "IF image_size >= 5000000 THEN FLAG_IMAGE",
            5000000
        )
        self.assertEqual(result, "FLAG_IMAGE")

    def test_invalid_rule(self):
        result = execute_rule(
            "INVALID SECURITY RULE",
            6000000
        )
        self.assertEqual(result, "INVALID_RULE")


if __name__ == "__main__":
    unittest.main()
