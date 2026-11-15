import io
import json
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
from wide_sdk.security import SecurityScanner, RuleLoader, load_advisories, fuzz_endpoint

class TestSecurityScanner(unittest.TestCase):
    def setUp(self) -> None:
        self.test_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.test_dir.name)

    def tearDown(self) -> None:
        self.test_dir.cleanup()

    def test_sqli_detection(self) -> None:
        vuln_file = self.root / "auth.js"
        vuln_file.write_text('const query = "SELECT * FROM users WHERE id = " + req.query.id;', encoding="utf-8")

        scanner = SecurityScanner(str(self.root))
        res = scanner.scan(".", min_severity="ALL")

        self.assertTrue(len(res.findings) >= 1)
        cwes = [f.cwe for f in res.findings]
        self.assertIn("CWE-89", cwes)
        finding = next(f for f in res.findings if f.cwe == "CWE-89")
        self.assertEqual(finding.severity, "CRITICAL")
        self.assertEqual(finding.line, 1)

    def test_clean_code(self) -> None:
        clean_file = self.root / "safe.py"
        clean_file.write_text('cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))', encoding="utf-8")

        scanner = SecurityScanner(str(self.root))
        res = scanner.scan(".", min_severity="ALL")

        self.assertEqual(len(res.findings), 0)

    def test_custom_rules_loading(self) -> None:
        custom_rules_file = self.root / "custom-rules.json"
        custom_rules_file.write_text(json.dumps([
            {
                "id": "wide/custom-dangerous-sink",
                "cwe": "CWE-999",
                "category": "Custom Category",
                "severity": "HIGH",
                "languages": ["all"],
                "pattern": "DANGEROUS_SINK\\(",
                "message": "Custom sink used",
                "remediation": "Do not call DANGEROUS_SINK"
            }
        ]), encoding="utf-8")

        sample_file = self.root / "test.js"
        sample_file.write_text('const res = DANGEROUS_SINK(foo);', encoding="utf-8")

        scanner = SecurityScanner(str(self.root), rules_path=str(custom_rules_file))
        res = scanner.scan(".", min_severity="ALL")

        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0].id, "wide/custom-dangerous-sink")

    def test_not_match_suppression_and_advisories(self) -> None:
        custom_rules_file = self.root / "not-match-rules.json"
        custom_rules_file.write_text(json.dumps([
            {
                "id": "wide/test-not-match",
                "cwe": "CWE-999",
                "category": "Test",
                "severity": "HIGH",
                "languages": ["js"],
                "pattern": r"unsafeFn\(",
                "not-match": "safeConstant",
                "message": "Unsafe call",
                "remediation": "Avoid unsafeFn"
            }
        ]), encoding="utf-8")

        sample_file = self.root / "sample.js"
        sample_file.write_text("unsafeFn(userInput);\nunsafeFn(safeConstant);\n", encoding="utf-8")

        scanner = SecurityScanner(str(self.root), rules_path=str(custom_rules_file))
        res = scanner.scan(".", min_severity="ALL")
        hits = [f for f in res.findings if f.id == "wide/test-not-match"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].line, 1)

        advisories = load_advisories(str(self.root))
        self.assertIsInstance(advisories, dict)
        self.assertIn("npm", advisories)

    def test_scan_single_file_and_skips_binary(self) -> None:
        (self.root / "bad.js").write_text('const q = "SELECT * FROM t WHERE id=" + req.query.id;', encoding="utf-8")
        (self.root / "fake.py").write_bytes(b"eval(x)\x00\x01\x02")
        scanner = SecurityScanner(str(self.root))
        single = scanner.scan("bad.js", min_severity="HIGH")
        self.assertEqual(single.total_files_scanned, 1)
        self.assertGreaterEqual(len(single.findings), 1)
        dir_res = scanner.scan(".", min_severity="ALL")
        scanned_files = [f.file for f in dir_res.findings]
        self.assertNotIn("fake.py", scanned_files)

    def test_fuzz_endpoint_post_uses_form_body(self) -> None:
        seen_requests = []

        class _FakeResp(io.BytesIO):
            status = 200
            def __enter__(self) -> "_FakeResp":
                return self
            def __exit__(self, *args: object) -> None:
                self.close()

        def fake_urlopen(req: object, timeout: float = 10.0) -> _FakeResp:
            seen_requests.append((
                getattr(req, "full_url", ""),
                getattr(req, "method", ""),
                getattr(req, "data", None),
            ))
            return _FakeResp(b"ok")

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            fuzz_endpoint("https://example.com/submit", "username", "xss", method="POST")

        self.assertGreaterEqual(len(seen_requests), 2)
        baseline_url, baseline_method, baseline_data = seen_requests[0]
        self.assertEqual(baseline_method, "POST")
        self.assertEqual(baseline_url, "https://example.com/submit")
        self.assertEqual(baseline_data, b"username=testbaselinevalue123")
        payload_url, payload_method, payload_data = seen_requests[1]
        self.assertEqual(payload_method, "POST")
        self.assertEqual(payload_url, "https://example.com/submit")
        self.assertTrue(payload_data and payload_data.startswith(b"username="))

if __name__ == "__main__":
    unittest.main()
