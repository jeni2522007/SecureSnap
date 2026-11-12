"""Tests for the forensic detection techniques."""

import os
import unittest

import numpy as np
from PIL import Image

from fixtures import TempDir, make_test_image

from modules.forensics import copy_move, ela, noise, scoring, steganography
from modules.metadata import detect_anomalies, extract_metadata


class TestErrorLevelAnalysis(unittest.TestCase):

    def setUp(self):
        self.temp = TempDir()
        self.image = make_test_image(self.temp.file("photo.jpg"))

    def tearDown(self):
        self.temp.cleanup()

    def test_produces_measurements_and_a_heatmap(self):
        outcome = ela.compute_ela(self.image, self.temp.path)

        self.assertIn("heatmap", outcome)
        self.assertTrue(os.path.exists(
            os.path.join(self.temp.path, outcome["heatmap"])
        ))

        measurements = outcome["measurements"]
        for key in ("mean_error", "hot_block_ratio", "error_uniformity"):
            self.assertIn(key, measurements)

    def test_a_flat_image_has_low_error(self):
        flat = os.path.join(self.temp.path, "flat.jpg")
        Image.new("RGB", (256, 256), (120, 120, 120)).save(flat, "JPEG", quality=90)

        outcome = ela.compute_ela(flat, self.temp.path)
        self.assertLess(outcome["measurements"]["mean_error"], 5.0)

    def test_edited_region_produces_a_different_error_surface(self):
        """A region pasted from a differently-compressed source must show up
        as a distinct error level compared with the untouched image."""
        generator = np.random.default_rng(3)

        # A smooth, photographic-looking base frame.
        small = generator.integers(30, 220, size=(16, 16, 3), dtype=np.uint8)
        base_pixels = np.asarray(
            Image.fromarray(small, "RGB").resize((256, 256), Image.BICUBIC)
        ).copy()

        # A donor region stored with a different compression history, exactly
        # as a region lifted from another photograph would be.
        donor_pixels = generator.integers(0, 255, size=(256, 256, 3), dtype=np.uint8)
        donor_jpeg = os.path.join(self.temp.path, "donor.jpg")
        Image.fromarray(donor_pixels, "RGB").save(donor_jpeg, "JPEG", quality=50)
        donor_array = np.asarray(Image.open(donor_jpeg).convert("RGB"))

        base_path = os.path.join(self.temp.path, "orig.png")
        edited_path = os.path.join(self.temp.path, "edited.png")

        edited_pixels = base_pixels.copy()
        edited_pixels[60:140, 60:140] = donor_array[60:140, 60:140]

        Image.fromarray(base_pixels, "RGB").save(base_path)
        Image.fromarray(edited_pixels, "RGB").save(edited_path)

        def patch_contrast(path):
            error = ela.error_map(path)
            region = error[60:140, 60:140].mean()
            outside = np.concatenate([
                error[:60, :].flatten(),
                error[140:, :].flatten(),
            ]).mean()
            return float(region - outside)

        # In the untouched frame the region and the rest of the picture are
        # statistically alike; after the edit they are not.
        self.assertLess(abs(patch_contrast(base_path)), 1.0)
        self.assertGreater(abs(patch_contrast(edited_path)), 2.0)


class TestCopyMoveDetection(unittest.TestCase):

    def setUp(self):
        self.temp = TempDir()

    def tearDown(self):
        self.temp.cleanup()

    def test_detects_a_cloned_region(self):
        generator = np.random.default_rng(5)
        pixels = generator.integers(0, 255, size=(300, 300, 3), dtype=np.uint8)

        pixels[20:100, 20:100] = pixels[180:260, 180:260]

        path = os.path.join(self.temp.path, "cloned.png")
        Image.fromarray(pixels, "RGB").save(path)

        outcome = copy_move.detect_copy_move(path, self.temp.path)
        self.assertTrue(outcome["available"])
        self.assertTrue(outcome["detected"])
        self.assertGreater(outcome["regions_count"], 0)
        self.assertGreater(outcome["duplicated_area_ratio"], 0)

    def test_an_ordinary_image_is_not_flagged(self):
        path = make_test_image(self.temp.file("plain.jpg"), size=(300, 300))
        outcome = copy_move.detect_copy_move(path, self.temp.path)
        self.assertTrue(outcome["available"])
        self.assertFalse(outcome["detected"])


class TestSteganography(unittest.TestCase):

    def setUp(self):
        self.temp = TempDir()

    def tearDown(self):
        self.temp.cleanup()

    def test_clean_image_is_not_flagged(self):
        path = make_test_image(self.temp.file("clean.jpg"), size=(256, 256))
        outcome = steganography.analyse_lsb(path, self.temp.path)

        self.assertTrue(outcome["available"])
        self.assertFalse(outcome["suspicious"])

    def test_lsb_embedded_image_is_flagged(self):
        generator = np.random.default_rng(9)
        pixels = generator.integers(0, 255, size=(256, 256, 3), dtype=np.uint8)

        # Embed a pseudo-random payload in the least significant bit.
        payload = generator.integers(0, 2, size=pixels.shape[:2])
        pixels[:, :, 0] = (pixels[:, :, 0] & 0xFE) | payload

        path = os.path.join(self.temp.path, "stego.png")
        Image.fromarray(pixels, "RGB").save(path)

        outcome = steganography.analyse_lsb(path, self.temp.path)
        self.assertTrue(outcome["suspicious"])

    def test_appended_data_is_detected(self):
        path = os.path.join(self.temp.path, "appended.jpg")
        make_test_image(path, size=(160, 160))
        with open(path, "ab") as handle:
            handle.write(b"\x00" * 512)

        outcome = steganography.detect_appended_data(path)
        self.assertTrue(outcome["appended_payload"])
        self.assertGreater(outcome["trailing_bytes"], 0)


class TestNoiseAndResampling(unittest.TestCase):

    def setUp(self):
        self.temp = TempDir()

    def tearDown(self):
        self.temp.cleanup()

    def test_jpeg_structure_is_reported(self):
        path = make_test_image(self.temp.file("photo.jpg"))
        outcome = noise.analyse_jpeg_structure(path)
        self.assertTrue(outcome["is_jpeg"])
        self.assertTrue(outcome["tables"])

    def test_resampling_analysis_returns_a_verdict(self):
        path = make_test_image(self.temp.file("photo.jpg"), size=(320, 320))
        outcome = noise.detect_resampling(path)
        self.assertTrue(outcome["available"])
        self.assertIn("upscaling_suspected", outcome)

    def test_noise_regions_are_measured(self):
        path = make_test_image(self.temp.file("photo.jpg"), size=(320, 320))
        outcome = noise.analyse_noise_regions(path)
        self.assertTrue(outcome["available"])
        self.assertIn("discontinuity_count", outcome)


class TestMetadata(unittest.TestCase):

    def setUp(self):
        self.temp = TempDir()

    def tearDown(self):
        self.temp.cleanup()

    def test_exif_is_extracted(self):
        path = make_test_image(self.temp.file("photo.jpg"), with_exif=True)
        meta = extract_metadata(path)

        self.assertTrue(meta["available"])
        self.assertEqual(meta["camera"]["make"], "Canon")
        self.assertEqual(meta["timestamps"]["datetime_original"],
                         "2024:01:15 10:00:00")

    def test_editing_software_is_flagged(self):
        path = make_test_image(self.temp.file("photo.jpg"), with_exif=True)
        meta = extract_metadata(path)

        codes = [anomaly["code"] for anomaly in meta["anomalies"]]
        self.assertIn("EDITING_SOFTWARE", codes)

    def test_missing_metadata_is_flagged(self):
        path = make_test_image(self.temp.file("plain.jpg"))
        meta = extract_metadata(path)

        codes = [anomaly["code"] for anomaly in meta["anomalies"]]
        self.assertIn("NO_METADATA", codes)

    def test_timestamp_contradiction_is_detected(self):
        result = detect_anomalies({
            "available": True,
            "camera": {},
            "timestamps": {
                "datetime_original": "2024:05:01 12:00:00",
                "datetime_digitized": "2024:05:01 12:30:00",
                "datetime": "2024:04:01 08:00:00",
            },
            "gps": {},
            "software": [],
            "xmp": {},
            "raw_tags": {},
            "image_properties": {},
            "anomalies": [],
        })

        codes = [anomaly["code"] for anomaly in result]
        self.assertIn("TIMESTAMP_REGRESSION", codes)

    def test_future_timestamp_is_detected(self):
        result = detect_anomalies({
            "available": True,
            "camera": {},
            "timestamps": {
                "datetime_original": "2099:01:01 10:00:00",
                "datetime_digitized": "2099:01:01 10:00:00",
                "datetime": "2099:01:01 10:00:00",
            },
            "gps": {},
            "software": [],
            "xmp": {},
            "raw_tags": {},
            "image_properties": {},
            "anomalies": [],
        })

        codes = [anomaly["code"] for anomaly in result]
        self.assertIn("FUTURE_TIMESTAMP", codes)


class TestScoring(unittest.TestCase):

    def test_score_grows_with_severity(self):
        mild = scoring.build_findings({
            "identity": {"mismatches": []},
            "metadata": {"anomalies": [
                {"severity": "LOW", "code": "X", "title": "x", "explanation": ""}
            ]},
        })
        severe = scoring.build_findings({
            "identity": {"mismatches": []},
            "metadata": {"anomalies": [
                {"severity": "CRITICAL", "code": "X", "title": "x", "explanation": ""}
            ]},
        })

        mild_score = scoring.score(mild)["score"]
        severe_score = scoring.score(severe)["score"]
        self.assertGreater(severe_score, mild_score)

    def test_critical_finding_forces_a_high_score(self):
        findings = scoring.build_findings({
            "identity": {"mismatches": []},
            "metadata": {"anomalies": [
                {"severity": "CRITICAL", "code": "X", "title": "x", "explanation": ""}
            ]},
        })
        result = scoring.score(findings)
        self.assertGreaterEqual(result["score"], 70)

    def test_verdict_reflects_the_score(self):
        verdict = scoring.verdict(75.0, [])
        self.assertIn("ALTERED", verdict["label"])
        self.assertEqual(verdict["risk_band"], "Elevated")
