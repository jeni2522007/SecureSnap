
import sys
import unittest
import tempfile
import os
from pathlib import Path

BACKEND_FOLDER = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND_FOLDER))

from modules.encryption import encrypt_image, decrypt_image
from modules.hashing import calculate_sha256


class TestEncryptionAndHashing(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        self.original_path = os.path.join(
            self.temp_dir.name,
            "test_image.jpg"
        )

        self.original_data = b"SecureSnap test image data"

        with open(self.original_path, "wb") as file:
            file.write(self.original_data)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_image_encryption(self):
        encrypted_folder = os.path.join(
            self.temp_dir.name,
            "encrypted"
        )

        encrypted_path, key = encrypt_image(
            self.original_path,
            encrypted_folder
        )

        self.assertTrue(os.path.exists(encrypted_path))

        with open(encrypted_path, "rb") as file:
            encrypted_data = file.read()

        self.assertNotEqual(encrypted_data, self.original_data)

    def test_image_decryption(self):
        encrypted_folder = os.path.join(
            self.temp_dir.name,
            "encrypted"
        )

        encrypted_path, key = encrypt_image(
            self.original_path,
            encrypted_folder
        )

        decrypted_path = os.path.join(
            self.temp_dir.name,
            "decrypted.jpg"
        )

        decrypt_image(
            encrypted_path,
            key,
            decrypted_path
        )

        with open(decrypted_path, "rb") as file:
            decrypted_data = file.read()

        self.assertEqual(decrypted_data, self.original_data)

    def test_sha256_hash(self):
        result = calculate_sha256(self.original_path)

        import hashlib

        expected = hashlib.sha256(
            self.original_data
        ).hexdigest()

        self.assertEqual(result, expected)


if __name__ == "__main__":
    unittest.main()
