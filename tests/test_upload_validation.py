
import sys
import unittest
from pathlib import Path
from io import BytesIO

# Add backend folder to Python path
BACKEND_FOLDER = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND_FOLDER))

from app import app


class TestUploadValidation(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_no_image_selected(self):
        response = self.client.post("/upload")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json["error"],
            "No image selected"
        )

    def test_empty_filename(self):
        response = self.client.post(
            "/upload",
            data={
                "image": (BytesIO(b""), "")
            },
            content_type="multipart/form-data"
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json["error"],
            "Please select an image"
        )

    def test_invalid_file_extension(self):
        response = self.client.post(
            "/upload",
            data={
                "image": (BytesIO(b"test data"), "test.gif")
            },
            content_type="multipart/form-data"
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("Only JPG", response.json["error"])

    def test_corrupted_image(self):
        response = self.client.post(
            "/upload",
            data={
                "image": (BytesIO(b"not a real image"), "test.jpg")
            },
            content_type="multipart/form-data"
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json["error"],
            "Invalid or corrupted image"
        )


if __name__ == "__main__":
    unittest.main()
