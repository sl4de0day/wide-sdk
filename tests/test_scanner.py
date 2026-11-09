import unittest
import tempfile
from pathlib import Path
from wide_sdk.security import SecurityScanner

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

        self.assertEqual(len(res.findings), 1)
        finding = res.findings[0]
        self.assertEqual(finding.category, "SQL Injection")
        self.assertEqual(finding.severity, "CRITICAL")
        self.assertEqual(finding.line, 1)

    def test_clean_code(self) -> None:
        clean_file = self.root / "safe.py"
        clean_file.write_text('cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))', encoding="utf-8")

        scanner = SecurityScanner(str(self.root))
        res = scanner.scan(".", min_severity="ALL")

        self.assertEqual(len(res.findings), 0)

if __name__ == "__main__":
    unittest.main()
