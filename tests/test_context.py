import unittest
from wide_sdk import ContextManager, ChatMessage

class TestContext(unittest.TestCase):
    def test_message_compaction(self) -> None:
        mgr = ContextManager(max_characters=100)
        messages = [
            ChatMessage(role="system", content="System instruction"),
            ChatMessage(role="user", content="Initial user query"),
            ChatMessage(role="assistant", content="Response 1"),
            ChatMessage(role="tool", content="Very long tool output exceeding limits " * 20),
        ]
        compacted = mgr.compact_messages(messages)
        self.assertTrue(len(compacted) > 0)
        self.assertEqual(compacted[0].role, "system")

if __name__ == "__main__":
    unittest.main()
