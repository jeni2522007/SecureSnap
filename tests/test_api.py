"""End-to-end API tests against a temporary database."""

import io
import os
import shutil
import tempfile
import unittest

from fixtures import BACKEND_FOLDER, make_test_image  # noqa: F401

from app import create_app
from config import Config


class TestConfig(Config):
    """Configuration that keeps every artefact inside a temporary directory."""

    DATA_DIR = None
    DATABASE_PATH = None
    EVIDENCE_FOLDER = None
    SEALED_FOLDER = None
    ANALYSIS_FOLDER = None
    KEY_FILE = None
    SECRET_KEY = "test-key"
    TESTING = True


class APITestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.mkdtemp(prefix="securesnap_api_test_")

        class TempConfig(TestConfig):
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
        self.image_path = os.path.join(self.temp, "sample.jpg")
        make_test_image(self.image_path, size=(320, 240))
        self.csrf_token = self._read_csrf_token()

    def _read_csrf_token(self):
        """Load the session token that the application issues to the browser."""
        response = self.client.get("/")
        marker = 'name="csrf-token" content="'
        start = response.get_data(as_text=True).find(marker)
        if start == -1:
            return ""
        start += len(marker)
        end = response.get_data(as_text=True).find('"', start)
        return response.get_data(as_text=True)[start:end]

    def _headers(self):
        return {"X-CSRF-Token": self.csrf_token}


class TestPages(APITestCase):

    def test_dashboard_renders(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"SecureSnap", response.data)

    def test_health_endpoint(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "success")

    def test_analysis_page_renders(self):
        self.assertEqual(self.client.get("/analyze").status_code, 200)

    def test_rules_page_renders(self):
        self.assertEqual(self.client.get("/rules").status_code, 200)


class TestAnalysis(APITestCase):

    def test_missing_file_is_rejected(self):
        response = self.client.post("/api/analyze", data={}, content_type="multipart/form-data",
                                      headers=self._headers())
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.json)

    def test_unsupported_extension_is_rejected(self):
        response = self.client.post(
            "/api/analyze",
            data={"image": (io.BytesIO(b"payload"), "payload.exe")},
            content_type="multipart/form-data",
            headers=self._headers(),
        )
        self.assertEqual(response.status_code, 400)

    def test_analysis_produces_a_full_result(self):
        with open(self.image_path, "rb") as handle:
            payload = handle.read()

        response = self.client.post(
            "/api/analyze",
            data={"image": (io.BytesIO(payload), "sample.jpg"), "save": "false"},
            content_type="multipart/form-data",
            headers=self._headers(),
        )

        self.assertEqual(response.status_code, 200)

        analysis = response.json["analysis"]
        self.assertIn("findings", analysis)
        self.assertIn("risk", analysis)
        self.assertIn("verdict", analysis)
        self.assertIn("facts", analysis)
        self.assertIn("summary", analysis)
        self.assertIn("rules", response.json)

        self.assertEqual(len(response.json["fingerprints"]["sha256"]), 64)

    def test_rules_are_evaluated_against_the_analysis(self):
        with open(self.image_path, "rb") as handle:
            payload = handle.read()

        response = self.client.post(
            "/api/analyze",
            data={"image": (io.BytesIO(payload), "sample.jpg")},
            content_type="multipart/form-data",
            headers=self._headers(),
        )

        rules = response.json["rules"]
        self.assertGreater(rules["evaluated"], 0)
        self.assertEqual(rules["errors"], [])


class TestEvidenceRegister(APITestCase):

    def _register(self, case_ref="FIR 2026/0001"):
        with open(self.image_path, "rb") as handle:
            payload = handle.read()

        return self.client.post(
            "/api/analyze",
            data={
                "image": (io.BytesIO(payload), "sample.jpg"),
                "save": "true",
                "case_ref": case_ref,
                "title": "Seized photograph",
                "description": "Recovered from the accused's handset.",
                "source": "Mobile phone",
                "collected_by": "HC/1234",
            },
            content_type="multipart/form-data",
            headers=self._headers(),
        )

    def test_evidence_can_be_registered(self):
        response = self._register()
        self.assertEqual(response.status_code, 200)
        self.assertIn("evidence", response.json)
        self.assertIn("id", response.json["evidence"])

    def test_registered_item_appears_in_the_listing(self):
        self._register("FIR 2026/0002")
        response = self.client.get("/api/evidence")
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(response.json["count"], 1)

    def test_filtering_by_case_reference(self):
        self._register("FIR 2026/0003")
        response = self.client.get("/api/evidence?case_ref=FIR+2026%2F0003")
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(response.json["count"], 1)

    def test_integrity_verification_passes_for_an_untouched_item(self):
        registered = self._register("FIR 2026/0004")
        evidence_id = registered.json["evidence"]["id"]

        response = self.client.post(f"/api/evidence/{evidence_id}/verify",
                                      headers=self._headers())
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["intact"])

    def test_integrity_verification_fails_after_tampering(self):
        registered = self._register("FIR 2026/0005")
        evidence_id = registered.json["evidence"]["id"]

        stored = os.path.join(
            self.app.config["UPLOAD_FOLDER"],
            registered.json["evidence"]["stored_filename"],
        )
        with open(stored, "wb") as handle:
            handle.write(b"tampered content")

        response = self.client.post(f"/api/evidence/{evidence_id}/verify",
                                      headers=self._headers())
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json["intact"])

    def test_duplicates_are_detected(self):
        self._register("FIR 2026/0006")
        self._register("FIR 2026/0007")

        response = self.client.get("/api/evidence/duplicates")
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(response.json["count"], 1)

    def test_evidence_can_be_updated(self):
        registered = self._register("FIR 2026/0008")
        evidence_id = registered.json["evidence"]["id"]

        response = self.client.patch(
            f"/api/evidence/{evidence_id}",
            json={"title": "Updated description"},
            headers=self._headers(),
        )
        self.assertEqual(response.status_code, 200)

        detail = self.client.get(f"/api/evidence/{evidence_id}")
        self.assertEqual(detail.json["evidence"]["title"], "Updated description")

    def test_report_json_export(self):
        registered = self._register("FIR 2026/0009")
        evidence_id = registered.json["evidence"]["id"]

        response = self.client.get(f"/api/report/{evidence_id}/json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("evidence", response.json)

    def test_csv_export(self):
        self._register("FIR 2026/0010")
        response = self.client.get("/api/export/evidence.csv")
        self.assertEqual(response.status_code, 200)
        self.assertIn("SHA-256", response.get_data(as_text=True))


class TestRuleManagement(APITestCase):

    def test_rules_are_seeded(self):
        response = self.client.get("/api/rules")
        self.assertEqual(response.status_code, 200)
        self.assertGreater(response.json["count"], 10)

    def test_a_rule_can_be_created(self):
        response = self.client.post("/api/rules", headers=self._headers(), json={
            "name": "TestCondition",
            "condition": "ela.hot_block_ratio > 0.5",
            "action": "ESCALATE_TEST",
            "severity": "HIGH",
            "description": "A rule used by the test suite.",
        })
        self.assertEqual(response.status_code, 201)
        rule_id = response.json["rule"]["id"]

        delete = self.client.delete(f"/api/rules/{rule_id}", headers=self._headers())
        self.assertEqual(delete.status_code, 200)

    def test_an_invalid_rule_is_rejected(self):
        response = self.client.post("/api/rules", headers=self._headers(), json={
            "name": "Broken",
            "condition": "this is not a rule",
            "action": "NOPE",
        })
        self.assertEqual(response.status_code, 400)

    def test_rule_validation_endpoint(self):
        response = self.client.post("/api/rules/validate", headers=self._headers(), json={
            "condition": "metadata.available == false",
        })
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["valid"])

    def test_a_rule_can_be_toggled(self):
        listing = self.client.get("/api/rules").json
        rule_id = listing["rules"][0]["id"]

        response = self.client.post(f"/api/rules/{rule_id}/toggle",
                                      headers=self._headers())
        self.assertEqual(response.status_code, 200)


class TestComparison(APITestCase):

    def test_comparison_requires_two_files(self):
        response = self.client.post("/api/compare", data={},
                                    content_type="multipart/form-data",
                                    headers=self._headers())
        self.assertEqual(response.status_code, 400)

    def test_two_images_can_be_compared(self):
        with open(self.image_path, "rb") as handle:
            payload = handle.read()

        response = self.client.post(
            "/api/compare",
            data={
                "first": (io.BytesIO(payload), "a.jpg"),
                "second": (io.BytesIO(payload), "b.jpg"),
            },
            content_type="multipart/form-data",
            headers=self._headers(),
        )

        self.assertEqual(response.status_code, 200)
        comparison = response.json["comparison"]
        self.assertTrue(comparison["available"])
        self.assertGreater(comparison["ssim"], 0.9)


if __name__ == "__main__":
    unittest.main()
