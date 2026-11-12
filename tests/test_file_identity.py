"""Tests for file identity detection, hashing and evidence sealing."""

import os
import unittest

from fixtures import TempDir, make_png, make_test_image

from modules import file_identity
from modules.encryption import seal_file, unseal_file, verify_sealed
from modules.hashing import (
    calculate_sha256,
    calculate_sha512,
    compare_fingerprints,
    ensure_key,
    fingerprint,
)


class TestFileIdentity(unittest.TestCase):

    def setUp(self):
        self.temp = TempDir()
        self.image = make_test_image(self.temp.file("photo.jpg"))

    def tearDown(self):
        self.temp.cleanup()

    def test_detects_a_real_jpeg(self):
        detected = file_identity.detect_format(self.image)
        self.assertEqual(detected["extension"], "jpg")
        self.assertEqual(detected["category"], "image")

    def test_detects_png(self):
        path = make_png(self.temp.file("image.png"))
        detected = file_identity.detect_format(path)
        self.assertEqual(detected["extension"], "png")

    def test_renamed_file_is_flagged(self):
        disguised = os.path.join(self.temp.path, "portrait.jpg")
        with open(self.image, "rb") as source:
            data = source.read()
        with open(disguised, "wb") as target:
            target.write(b"%PDF-1.4\n" + data)

        claim = file_identity.compare_claim(disguised, "portrait.jpg")
        self.assertEqual(claim["severity"], "HIGH")
        self.assertFalse(claim["identity_trusted"])

        codes = [m["field"] for m in claim["mismatches"]]
        self.assertIn("extension", codes)

    def test_executable_content_is_critical(self):
        path = os.path.join(self.temp.path, "photo.jpg")
        with open(path, "wb") as handle:
            handle.write(b"MZ\x90\x00" + b"\x00" * 200)

        claim = file_identity.compare_claim(path, "photo.jpg")
        self.assertEqual(claim["severity"], "CRITICAL")

    def test_matching_extension_produces_no_mismatch(self):
        claim = file_identity.compare_claim(self.image, "photo.jpg")
        self.assertEqual(claim["severity"], "NONE")
        self.assertTrue(claim["identity_trusted"])

    def test_embedded_payload_is_detected(self):
        path = os.path.join(self.temp.path, "sneaky.jpg")
        with open(path, "wb") as handle:
            handle.write(b"\xff\xd8\xff\xe0" + b"\x00" * 100)
            handle.write(b"PK\x03\x04" + b"payload" * 50)

        detected = file_identity.detect_format(path)
        self.assertTrue(detected["embedded_payloads"])

    def test_entropy_is_reported(self):
        entropy = file_identity.analyse_entropy(self.image)
        self.assertGreater(entropy["overall_bits_per_byte"], 0)
        self.assertIn("interpretation", entropy)


class TestHashing(unittest.TestCase):

    def setUp(self):
        self.temp = TempDir()
        self.image = make_test_image(self.temp.file("photo.jpg"))

    def tearDown(self):
        self.temp.cleanup()

    def test_sha256_is_stable(self):
        first = calculate_sha256(self.image)
        second = calculate_sha256(self.image)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)

    def test_sha512_is_stable(self):
        self.assertEqual(len(calculate_sha512(self.image)), 128)

    def test_fingerprint_contains_size(self):
        result = fingerprint(self.image)
        self.assertEqual(result["size_bytes"], os.path.getsize(self.image))

    def test_comparison_detects_a_change(self):
        original = fingerprint(self.image)

        tampered = self.temp.file("tampered.jpg")
        with open(tampered, "wb") as handle:
            handle.write(b"completely different content")

        outcome = compare_fingerprints(original, fingerprint(tampered))
        self.assertFalse(outcome["match"])
        self.assertIn("sha256", outcome["differences"])

    def test_comparison_confirms_an_unchanged_file(self):
        original = fingerprint(self.image)
        outcome = compare_fingerprints(original, fingerprint(self.image))
        self.assertTrue(outcome["match"])


class TestSealing(unittest.TestCase):

    def setUp(self):
        self.temp = TempDir()
        self.image = make_test_image(self.temp.file("photo.jpg"))
        self.key = ensure_key(os.path.join(self.temp.path, "evidence.key"))

    def tearDown(self):
        self.temp.cleanup()

    def test_sealed_copy_is_not_readable(self):
        sealed = seal_file(self.image, self.temp.path, self.key)

        with open(sealed, "rb") as handle:
            sealed_bytes = handle.read()
        with open(self.image, "rb") as handle:
            original_bytes = handle.read()

        self.assertNotEqual(sealed_bytes, original_bytes)
        self.assertNotIn(b"\xff\xd8", sealed_bytes[:64])

    def test_unsealing_restores_the_original(self):
        sealed = seal_file(self.image, self.temp.path, self.key)
        restored = self.temp.file("restored.jpg")
        unseal_file(sealed, self.key, restored)

        self.assertEqual(
            calculate_sha256(restored),
            calculate_sha256(self.image),
        )

    def test_verification_detects_tampering(self):
        sealed = seal_file(self.image, self.temp.path, self.key)
        outcome = verify_sealed(sealed, self.key, calculate_sha256(self.image))
        self.assertTrue(outcome["authenticated"])
        self.assertTrue(outcome["matches_original"])

        with open(sealed, "wb") as handle:
            handle.write(b"corrupted sealed content")

        with self.assertRaises(ValueError):
            verify_sealed(sealed, self.key, calculate_sha256(self.image))

    def test_key_is_generated_once(self):
        path = os.path.join(self.temp.path, "generated.key")
        first = ensure_key(path)
        second = ensure_key(path)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
