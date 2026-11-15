import unittest
from wide_sdk import ContextManager, ChatMessage, ToolCall

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

    def test_compaction_preserves_assistant_tool_call_pair(self) -> None:
        mgr = ContextManager(max_characters=120)
        tc = ToolCall(id="call-1", name="read_file", arguments={"path": "a.txt"})
        messages = [
            ChatMessage(role="system", content="Sys"),
            ChatMessage(role="user", content="Old prompt " * 12),
            ChatMessage(role="assistant", content="", tool_calls=[tc]),
            ChatMessage(role="tool", content="Short result", tool_call_id="call-1", name="read_file"),
        ]
        compacted = mgr.compact_messages(messages)
        tool_indices = [i for i, m in enumerate(compacted) if m.role == "tool"]
        if tool_indices:
            first_tool = tool_indices[0]
            self.assertGreater(first_tool, 0)
            self.assertEqual(compacted[first_tool - 1].role, "assistant")
            self.assertTrue(bool(compacted[first_tool - 1].tool_calls))

if __name__ == "__main__":
    unittest.main()
