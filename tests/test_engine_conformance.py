import json
import unittest
from pathlib import Path

from wide_sdk.security.taint import analyze_project_flows, is_likely_real_secret

SUITE_PATH = Path(__file__).resolve().parent / "vendor" / "wide-engine" / "conformance.json"


def _normalize(finding):
    return {
        "ruleId": finding.id,
        "cwe": finding.cwe,
        "category": finding.category,
        "severity": finding.severity,
        "file": finding.file,
        "line": finding.line,
        "endLine": finding.end_line,
        "message": finding.message,
        "snippet": finding.snippet,
        "crossFile": bool(finding.cross_file),
    }


class EngineConformanceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with SUITE_PATH.open(encoding="utf-8") as fh:
            cls.suite = json.load(fh)

    def test_suite_is_not_empty(self):
        self.assertGreater(len(self.suite["projects"]), 0)
        self.assertGreater(len(self.suite["secrets"]), 0)

    def test_taint_matches_wide_rules_engine(self):
        for project in self.suite["projects"]:
            with self.subTest(project=project["name"]):
                actual = [_normalize(f) for f in analyze_project_flows(project["files"])]
                self.assertEqual(actual, project["expected"])

    def test_secret_heuristic_matches_wide_rules_engine(self):
        for case in self.suite["secrets"]:
            with self.subTest(file=case["file"], line=case["line"]):
                self.assertEqual(is_likely_real_secret(case["line"], case["file"]), case["expected"])


if __name__ == "__main__":
    unittest.main()
