
import re


def execute_rule(rule_text, image_size):

    pattern = (
        r"IF\s+image_size\s*(>|<|>=|<=|==)\s*(\d+)"
        r"\s+THEN\s+(FLAG_IMAGE|ALLOW_IMAGE)"
    )

    match = re.fullmatch(
        pattern,
        rule_text.strip(),
        re.IGNORECASE
    )

    if not match:
        return "INVALID_RULE"

    operator = match.group(1)
    threshold = int(match.group(2))
    action = match.group(3).upper()

    conditions = {
        ">": image_size > threshold,
        "<": image_size < threshold,
        ">=": image_size >= threshold,
        "<=": image_size <= threshold,
        "==": image_size == threshold
    }

    if conditions[operator]:
        return action

    return "ALLOW_IMAGE"


if __name__ == "__main__":

    print("===== SecureSnap Rule Compiler =====")

    rule = input("Enter your security rule: ")
    image_size = int(input("Enter image size in bytes: "))

    result = execute_rule(rule, image_size)

    print("Compiler Result:", result)
