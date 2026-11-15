from typing import List
from .types import ChatMessage

class ContextManager:
    def __init__(self, max_characters: int = 40000) -> None:
        self.max_characters = max_characters

    def compact_messages(self, messages: List[ChatMessage]) -> List[ChatMessage]:
        total_chars = sum(len(m.content) for m in messages if m.content)
        if total_chars <= self.max_characters and len(messages) <= 20:
            return messages

        system_msg = messages[0] if messages else None
        initial_user_msg = next((m for i, m in enumerate(messages) if i > 0 and m.role == "user"), None)
        slice_start = max(1, len(messages) - 10)
        while slice_start > 1 and messages[slice_start].role == "tool":
            slice_start -= 1
        recent_messages = messages[slice_start:]

        compacted: List[ChatMessage] = []
        if system_msg:
            compacted.append(system_msg)
        if initial_user_msg and not any(m is initial_user_msg for m in recent_messages):
            compacted.append(initial_user_msg)

        compacted.append(ChatMessage(
            role="system",
            content="[Context Compaction] Earlier tool interactions were summarized to preserve context window limits. Continue with current objective."
        ))

        for msg in recent_messages:
            if msg.role == "tool" and len(msg.content) > 2000:
                compacted.append(ChatMessage(
                    role="tool",
                    content=msg.content[:2000] + "\n... [Output compacted]",
                    tool_call_id=msg.tool_call_id,
                    name=msg.name
                ))
            else:
                compacted.append(msg)

        return compacted
