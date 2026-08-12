"""
test_analyzer.py
-----------------
Basic unit tests for the non-interactive, non-OS-dependent modules:
password strength, security classification, scoring, and
recommendation generation. Report generation is smoke-tested with
tempfile output.

Run with:  python -m unittest test_analyzer.py -v
"""

import os
import tempfile
import unittest

import password_analyzer
import security_analyzer
import scoring
import recommendations as rec_module
import report_generator


class TestPasswordAnalyzer(unittest.TestCase):
    def test_weak_short_password(self):
        result = password_analyzer.analyze_password_strength("abc123")
        self.assertIn(result["label"], ("Very Weak", "Weak"))

    def test_common_password_penalized(self):
        result = password_analyzer.analyze_password_strength("password1")
        self.assertTrue(result["checks"]["is_common_password"])
        self.assertLess(result["score"], 50)

    def test_strong_password(self):
        result = password_analyzer.analyze_password_strength("Tr7$qLp9!zXw#2mN")
        self.assertIn(result["label"], ("Strong", "Very Strong"))

    def test_sequential_pattern_detected(self):
        result = password_analyzer.analyze_password_strength("abcd1234EFGH")
        self.assertTrue(result["checks"]["has_sequential_pattern"])

    def test_repeated_pattern_detected(self):
        result = password_analyzer.analyze_password_strength("aaaaBBBB1111")
        self.assertTrue(result["checks"]["has_repeated_pattern"])

    def test_empty_password(self):
        result = password_analyzer.analyze_password_strength("")
        self.assertEqual(result["label"], "Very Weak")

    def test_password_not_leaked_in_result(self):
        secret = "SuperSecretPassphrase123!"
        result = password_analyzer.analyze_password_strength(secret)
        self.assertNotIn(secret, str(result))


class TestSecurityClassification(unittest.TestCase):
    def test_open_network(self):
        result = security_analyzer.classify_security("Open", "None")
        self.assertEqual(result["type"], "Open")
        self.assertEqual(result["risk_level"], "critical")

    def test_wep(self):
        result = security_analyzer.classify_security("WEP", "WEP")
        self.assertEqual(result["type"], "WEP")

    def test_wpa2_aes(self):
        result = security_analyzer.classify_security("WPA2-Personal", "CCMP")
        self.assertEqual(result["type"], "WPA2")
        self.assertEqual(result["cipher"], "AES/CCMP")

    def test_wpa2_tkip(self):
        result = security_analyzer.classify_security("WPA2-Personal", "TKIP")
        self.assertEqual(result["cipher"], "TKIP")

    def test_wpa3(self):
        result = security_analyzer.classify_security("WPA3-SAE", "SAE")
        self.assertEqual(result["type"], "WPA3")
        self.assertEqual(result["risk_level"], "none")

    def test_mixed_mode(self):
        result = security_analyzer.classify_security("WPA2/WPA3", "AES")
        self.assertEqual(result["type"], "WPA2/WPA3-Mixed")

    def test_unknown_when_no_data(self):
        result = security_analyzer.classify_security(None, None)
        self.assertEqual(result["type"], security_analyzer.UNKNOWN)

    def test_wps_enabled(self):
        self.assertEqual(security_analyzer.classify_wps("Enabled"), "Enabled")

    def test_wps_disabled(self):
        self.assertEqual(security_analyzer.classify_wps("Disabled"), "Disabled")

    def test_wps_unknown(self):
        self.assertEqual(security_analyzer.classify_wps(None), security_analyzer.UNKNOWN)


class TestScoring(unittest.TestCase):
    def test_wpa3_scores_high(self):
        sec_info = {"type": "WPA3", "cipher": "SAE/GCMP"}
        result = scoring.calculate_security_score(sec_info, "Disabled")
        self.assertGreaterEqual(result["score"], 40)

    def test_open_network_scores_low(self):
        sec_info = {"type": "Open", "cipher": security_analyzer.UNKNOWN}
        result = scoring.calculate_security_score(sec_info, security_analyzer.UNKNOWN)
        self.assertLessEqual(result["score"], 30)

    def test_score_within_bounds(self):
        sec_info = {"type": "WPA3", "cipher": "SAE"}
        pw_result = {"score": 100, "label": "Very Strong"}
        result = scoring.calculate_security_score(sec_info, "Disabled", pw_result)
        self.assertLessEqual(result["score"], 100)
        self.assertGreaterEqual(result["score"], 0)

    def test_wps_enabled_reduces_score(self):
        sec_info = {"type": "WPA2", "cipher": "AES/CCMP"}
        with_wps = scoring.calculate_security_score(sec_info, "Enabled")
        without_wps = scoring.calculate_security_score(sec_info, "Disabled")
        self.assertLess(with_wps["score"], without_wps["score"])

    def test_breakdown_not_empty(self):
        sec_info = {"type": "WPA2", "cipher": "AES/CCMP"}
        result = scoring.calculate_security_score(sec_info, "Disabled")
        self.assertGreater(len(result["breakdown"]), 0)


class TestRecommendations(unittest.TestCase):
    def test_open_network_recommends_encryption(self):
        sec_info = {"type": "Open", "cipher": security_analyzer.UNKNOWN}
        recs = rec_module.generate_recommendations(sec_info, security_analyzer.UNKNOWN)
        self.assertTrue(any("encryption" in r.lower() for r in recs))

    def test_wps_enabled_recommends_disable(self):
        sec_info = {"type": "WPA2", "cipher": "AES/CCMP"}
        recs = rec_module.generate_recommendations(sec_info, "Enabled")
        self.assertTrue(any("wps" in r.lower() for r in recs))

    def test_wpa3_no_protocol_change_needed(self):
        sec_info = {"type": "WPA3", "cipher": "SAE"}
        recs = rec_module.generate_recommendations(sec_info, "Disabled")
        self.assertTrue(any("wpa3" in r.lower() for r in recs))

    def test_recommendations_deduplicated(self):
        sec_info = {"type": "WPA2", "cipher": "AES/CCMP"}
        recs = rec_module.generate_recommendations(sec_info, "Disabled")
        self.assertEqual(len(recs), len(set(recs)))


class TestReportGeneration(unittest.TestCase):
    def setUp(self):
        self.network_info = {
            "ssid": "TestNet", "interface": "wlan0", "status": "Connected",
            "signal_strength": "-50 dBm", "channel": "6", "frequency": "2437 MHz",
        }
        self.security_info = {"type": "WPA2", "cipher": "AES/CCMP", "risk_level": "low"}
        self.wps_status = "Disabled"
        self.score_result = scoring.calculate_security_score(self.security_info, self.wps_status)
        self.recs = rec_module.generate_recommendations(self.security_info, self.wps_status)
        self.report_data = report_generator.build_report_data(
            self.network_info, self.security_info, self.wps_status,
            self.score_result, self.recs,
        )

    def test_txt_export_creates_file(self):
        path = report_generator.export_txt(self.report_data)
        self.assertTrue(os.path.exists(path))
        os.remove(path)

    def test_json_export_creates_valid_json(self):
        import json
        path = report_generator.export_json(self.report_data)
        with open(path) as f:
            data = json.load(f)
        self.assertEqual(data["network"]["ssid"], "TestNet")
        os.remove(path)

    def test_html_export_creates_file(self):
        path = report_generator.export_html(self.report_data)
        self.assertTrue(os.path.exists(path))
        with open(path) as f:
            content = f.read()
        self.assertIn("Wi-Fi Security Assessment", content)
        os.remove(path)


if __name__ == "__main__":
    unittest.main()
