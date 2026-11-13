"""Security regression tests.

These tests exist to ensure that the hardening added to the application
cannot be quietly removed. Each one corresponds to a weakness that was
present at some point during development.
"""

import io
import os
import re
import shutil
import tempfile
import unittest

from fixtures import BACKEND_FOLDER, make_test_image  # noqa: F401

from app import create_app
from config import Config


class SecurityConfig(Config):
    """Configuration that keeps every artefact inside a temporary directory."""

    DATA_DIR = None
    DATABASE_PATH = None
    EVIDENCE_FOLDER = None
    SEALED_FOLDER = None
    ANALYSIS_FOLDER = None
    KEY_FILE = None
    SECRET_KEY = "test-key"
    TESTING = True
    ALLOWED_HOSTS = ["127.0.0.1", "localhost"]


class SecurityTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.mkdtemp(prefix="securesnap_security_test_")

        class TempConfig(SecurityConfig):
            pass

        TempConfig.DATA_DIR = os.path.join(cls.temp, "data")
        TempConfig.DATABASE_PATH = os.path.join(cls.temp, "data", "test.db")
        TempConfig.EVIDENCE_FOLDER = os.path.join(cls.temp, "data", "evidence")
        TempConfig.SEALED_FOLDER = os.path.join(cls.temp, "data", "sealed")
        TempConfig.ANALYSIS_FOLDER = os.path.join(cls.temp, "data", "analysis")
        TempConfig.KEY_FILE = os.path.join(cls.temp, "data", "evidence.key")

        cls.app = create_app(TempConfig)
        cls.app.config["TESTING"] = True

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp, ignore_errors=True)

    def setUp(self):
        self.client = self.app.test_client()
        self.csrf_token = self._read_csrf_token()
        self.headers = {"X-CSRF-Token": self.csrf_token}

    def _read_csrf_token(self):
        response = self.client.get("/")
        text = response.get_data(as_text=True)
        match = re.search(r'name="csrf-token" content="([^"]+)"', text)
        return match.group(1) if match else ""

    def _image_bytes(self):
        path = os.path.join(self.temp, "sample.jpg")
        make_test_image(path, size=(160, 120))
        with open(path, "rb") as handle:
            return handle.read()


class TestPathTraversal(SecurityTestCase):

    def test_a_traversing_filename_cannot_escape_the_working_directory(self):
        """A filename containing traversal sequences must not write outside."""
        escape_target = os.path.abspath(
            os.path.join(self.temp, "..", "..", "TRAVERSAL_PROOF.jpg")
        )
        self.assertFalse(os.path.exists(escape_target))

        self.client.post(
            "/api/analyze",
            data={"image": (io.BytesIO(self._image_bytes()),
                           "../../../../TRAVERSAL_PROOF.jpg")},
            content_type="multipart/form-data",
            headers=self.headers,
        )

        # The request may succeed, but the file must not have landed outside.
        self.assertFalse(
            os.path.exists(escape_target),
            "A traversing filename wrote a file outside the working directory",
        )

    def test_a_traversing_filename_is_stored_under_a_safe_name(self):
        response = self.client.post(
            "/api/analyze",
            data={
                "image": (io.BytesIO(self._image_bytes()),
                          "../../../../evidence.jpg"),
                "save": "true",
                "case_ref": "FIR 1/1",
            },
            content_type="multipart/form-data",
            headers=self.headers,
        )

        self.assertEqual(response.status_code, 200)

        stored = response.json["evidence"]["stored_filename"]
        self.assertNotIn("..", stored)
        self.assertNotIn("/", stored)
        self.assertNotIn("\\", stored)

    def test_the_artefact_route_does_not_serve_files_outside_its_folder(self):
        response = self.client.get("/analysis/../../app.py")
        self.assertNotEqual(response.status_code, 200)


class TestCrossSiteRequestForgery(SecurityTestCase):

    def test_a_post_without_a_token_is_refused(self):
        response = self.client.post(
            "/api/rules",
            json={"name": "NoToken", "condition": "a == 1", "action": "X"},
        )
        self.assertEqual(response.status_code, 403)

    def test_a_post_with_a_wrong_token_is_refused(self):
        response = self.client.post(
            "/api/rules",
            json={"name": "BadToken", "condition": "a == 1", "action": "X"},
            headers={"X-CSRF-Token": "not-the-right-token"},
        )
        self.assertEqual(response.status_code, 403)

    def test_a_post_with_a_valid_token_is_accepted(self):
        response = self.client.post(
            "/api/rules",
            json={
                "name": "GoodToken",
                "condition": "a == 1",
                "action": "ACCEPTED",
                "severity": "LOW",
            },
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 201)

    def test_a_request_from_another_origin_is_refused(self):
        response = self.client.post(
            "/api/rules",
            json={"name": "CrossSite", "condition": "a == 1", "action": "X"},
            headers={"Origin": "http://evil.example.com"},
        )
        self.assertEqual(response.status_code, 403)

    def test_a_request_with_an_unexpected_host_is_refused(self):
        response = self.client.post(
            "/api/rules",
            json={"name": "BadHost", "condition": "a == 1", "action": "X"},
            headers={"Host": "attacker.example.com"},
        )
        self.assertEqual(response.status_code, 403)

    def test_read_only_requests_are_not_blocked(self):
        response = self.client.get("/api/rules")
        self.assertEqual(response.status_code, 200)


class TestSecurityHeaders(SecurityTestCase):

    def test_every_response_carries_the_hardening_headers(self):
        response = self.client.get("/")

        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")

    def test_script_sources_are_restricted_to_the_same_origin(self):
        csp = self.client.get("/").headers["Content-Security-Policy"]
        directives = {
            directive.split()[0]: directive
            for directive in (part.strip() for part in csp.split(";"))
            if directive
        }

        self.assertEqual(directives.get("script-src"), "script-src 'self'")
        self.assertNotIn("unsafe-inline", directives.get("script-src", ""))

    def test_the_session_cookie_is_not_readable_by_script(self):
        # A fresh client is used because the cookie is only issued when the
        # session first changes.
        response = self.app.test_client().get("/")
        cookies = response.headers.get("Set-Cookie") or ""
        self.assertIn("session=", cookies)
        self.assertIn("HttpOnly", cookies)
        self.assertIn("SameSite=Strict", cookies)


class TestErrorHandling(SecurityTestCase):

    def test_internal_errors_do_not_leak_details_to_the_client(self):
        """A failure must not disclose internal paths or tracebacks."""
        response = self.client.get("/api/evidence/999999")
        self.assertEqual(response.status_code, 404)
        self.assertNotIn("Traceback", response.get_data(as_text=True))
        self.assertNotIn("sqlite", response.get_data(as_text=True).lower())

    def test_a_missing_file_does_not_leak_the_server_path(self):
        response = self.client.post(
            "/api/analyze",
            data={"image": (io.BytesIO(b"not an image"), "broken.jpg")},
            content_type="multipart/form-data",
            headers=self.headers,
        )
        body = response.get_data(as_text=True)
        self.assertNotIn(self.temp, body)
        self.assertNotIn("Traceback", body)


class TestUploadLimits(SecurityTestCase):

    def test_an_oversized_request_is_refused(self):
        oversized = b"\xff\xd8\xff" + b"\x00" * (26 * 1024 * 1024)
        response = self.client.post(
            "/api/analyze",
            data={"image": (io.BytesIO(oversized), "huge.jpg")},
            content_type="multipart/form-data",
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 413)


if __name__ == "__main__":
    unittest.main()
