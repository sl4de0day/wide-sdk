import json
import unittest
import tempfile
from pathlib import Path
from wide_sdk.security import SecurityScanner, RuleLoader

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

if __name__ == "__main__":
    unittest.main()
