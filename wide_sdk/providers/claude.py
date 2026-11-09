import os
import json
import urllib.request
import urllib.error
from typing import List, Tuple, Optional
from ..types import ChatMessage, ToolDefinition, ToolCall
from .base import BaseProvider

class ClaudeProvider(BaseProvider):
    name = "claude"

    def __init__(self, api_key: Optional[str] = None, model: str = "claude-3-7-sonnet-20250219") -> None:
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model
        if not self.api_key:
            raise ValueError("Anthropic API key is required. Set ANTHROPIC_API_KEY environment variable or pass api_key.")

    def chat(
        self,
        messages: List[ChatMessage],
        tools: List[ToolDefinition]
    ) -> Tuple[str, Optional[List[ToolCall]]]:
        system_msg = next((m for m in messages if m.role == "system"), None)
        chat_msgs = [m for m in messages if m.role != "system"]

        anthropic_messages = []
        for m in chat_msgs:
            if m.role == "tool":
                anthropic_messages.append({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": m.tool_call_id or "tool_call",
                        "content": m.content
                    }]
                })
            elif m.role == "assistant" and m.tool_calls:
                blocks = []
                if m.content:
                    blocks.append({"type": "text", "text": m.content})
                for tc in m.tool_calls:
                    blocks.append({
                        "type": "tool_use",
                        "id": tc.id,
                        "name": tc.name,
                        "input": tc.arguments
                    })
                anthropic_messages.append({"role": "assistant", "content": blocks})
            else:
                anthropic_messages.append({"role": m.role, "content": m.content})

        anthropic_tools = [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": {
                    "type": "object",
                    "properties": t.parameters.get("properties", {}),
                    "required": t.parameters.get("required", [])
                }
            }
            for t in tools
        ]

        payload = {
            "model": self.model,
            "max_tokens": 4096,
            "messages": anthropic_messages
        }
        if system_msg:
            payload["system"] = system_msg.content
        if anthropic_tools:
            payload["tools"] = anthropic_tools

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01"
            },
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=60.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_msg = e.read().decode("utf-8") if e.fp else str(e)
            raise RuntimeError(f"Claude API error ({e.code}): {err_msg}")

        content_blocks = data.get("content", [])
        text_content = ""
        tool_calls: List[ToolCall] = []

        for block in content_blocks:
            if block.get("type") == "text":
                text_content += block.get("text", "")
            elif block.get("type") == "tool_use":
                tool_calls.append(ToolCall(
                    id=block.get("id", f"call_{len(tool_calls)}"),
                    name=block.get("name", ""),
                    arguments=block.get("input", {})
                ))

        return text_content, (tool_calls if tool_calls else None)
