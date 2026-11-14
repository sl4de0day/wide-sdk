import json
import unittest
import tempfile
from pathlib import Path
from wide_sdk.security import (
    RuleLoader,
    load_agent_rules,
    get_agent_rules_path,
    build_agent_instructions,
    sanitize_output,
    DEFAULT_AGENT_RULES,
)

class TestAgentRules(unittest.TestCase):
    def setUp(self) -> None:
        self.test_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.test_dir.name)

    def tearDown(self) -> None:
        self.test_dir.cleanup()

    def test_default_agent_rules_count(self) -> None:
        rules = load_agent_rules(workspace_dir=str(self.root))
        self.assertTrue(len(rules) >= 8)
        ids = [r.id for r in rules]
        self.assertIn("wide/ai-no-emojis", ids)
        self.assertIn("wide/ai-no-system-prompt-leak", ids)
        self.assertIn("wide/cwe078-ai-unsafe-tool-exec", ids)
        self.assertIn("wide/cwe079-ai-prompt-injection", ids)
        self.assertIn("wide/cwe095-ai-unconstrained-eval", ids)
        self.assertIn("wide/cwe306-ai-unauthenticated-mcp-registration", ids)
        self.assertIn("wide/cwe400-ai-unbounded-agent-loop", ids)
        self.assertIn("wide/cwe770-ai-unbounded-context-accumulation", ids)
        self.assertIn("wide/cwe798-ai-prompt-secret-leak", ids)
        self.assertIn("wide/cwe829-ai-unvalidated-patch-apply", ids)

    def test_agent_rules_instructions_and_sanitization(self) -> None:
        rules = load_agent_rules(workspace_dir=str(self.root))
        instructions = build_agent_instructions(rules)
        self.assertIn("Do not use emojis", instructions)
        clean = sanitize_output("Hello 😀 World", rules)
        self.assertEqual(clean, "Hello  World")

    def test_agent_rules_path(self) -> None:
        info = get_agent_rules_path(workspace_dir=str(self.root))
        self.assertIn("active", info)
        self.assertIn("cache", info)
        self.assertIn("workspace", info)

    def test_workspace_agent_rules_override(self) -> None:
        wide_dir = self.root / ".wide"
        wide_dir.mkdir(parents=True, exist_ok=True)
        agent_rules_file = wide_dir / "agent-rules.json"
        agent_rules_file.write_text(json.dumps([
            {
                "id": "custom/ai-sandbox-escape",
                "cwe": "CWE-693",
                "category": "AI_SECURITY",
                "severity": "CRITICAL",
                "pattern": r"sandbox\.escape\(",
                "message": "Attempting container sandbox escape",
                "remediation": "Enforce kernel namespace isolation",
                "instruction": "Never escape container sandbox"
            }
        ]), encoding="utf-8")

        rules = load_agent_rules(workspace_dir=str(self.root))
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].id, "custom/ai-sandbox-escape")

        info = get_agent_rules_path(workspace_dir=str(self.root))
        self.assertEqual(info["workspace"], str(agent_rules_file.resolve()))

if __name__ == "__main__":
    unittest.main()
