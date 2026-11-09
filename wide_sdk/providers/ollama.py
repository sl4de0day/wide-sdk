import json
import urllib.request
import urllib.error
from typing import List, Tuple, Optional
from ..types import ChatMessage, ToolDefinition, ToolCall
from .base import BaseProvider

class OllamaProvider(BaseProvider):
    name = "ollama"

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "deepseek-r1:7b") -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model

    def chat(
        self,
        messages: List[ChatMessage],
        tools: List[ToolDefinition]
    ) -> Tuple[str, Optional[List[ToolCall]]]:
        formatted_messages = [
            {"role": m.role, "content": m.content}
            for m in messages
        ]

        formatted_tools = [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters
                }
            }
            for t in tools
        ]

        payload = {
            "model": self.model,
            "messages": formatted_messages,
            "stream": False,
            "options": {"temperature": 0.2}
        }
        if formatted_tools:
            payload["tools"] = formatted_tools

        url = f"{self.base_url}/api/chat"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=120.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as e:
            raise RuntimeError(f"Failed to connect to Ollama at {self.base_url}: {str(e)}")

        msg = data.get("message", {})
        content = msg.get("content", "")
        tool_calls: List[ToolCall] = []

        if "tool_calls" in msg:
            for tc in msg["tool_calls"]:
                fn = tc.get("function", {})
                tool_calls.append(ToolCall(
                    id=f"call_{len(tool_calls)}",
                    name=fn.get("name", ""),
                    arguments=fn.get("arguments", {})
                ))

        return content, (tool_calls if tool_calls else None)
