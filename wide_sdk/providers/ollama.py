from typing import Any, Dict, List, Tuple, Optional
from ..types import ChatMessage, ToolDefinition, ToolCall
from .base import BaseProvider
from .http import post_json_with_retry

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
        formatted_messages: List[Dict[str, Any]] = []
        for m in messages:
            if m.role == "tool":
                item: Dict[str, Any] = {"role": "tool", "content": m.content}
                if m.name:
                    item["name"] = m.name
                formatted_messages.append(item)
            elif m.role == "assistant" and m.tool_calls:
                formatted_messages.append({
                    "role": "assistant",
                    "content": m.content or "",
                    "tool_calls": [
                        {"function": {"name": tc.name, "arguments": tc.arguments}}
                        for tc in m.tool_calls
                    ],
                })
            else:
                formatted_messages.append({"role": m.role, "content": m.content})

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
        data = post_json_with_retry(
            url,
            payload,
            {"Content-Type": "application/json"},
            timeout=120.0,
            provider_name=f"Ollama ({self.base_url})",
            max_retries=1,
        )

        msg = data.get("message", {})
        content = msg.get("content", "")
        tool_calls: List[ToolCall] = []

        for tc in (msg.get("tool_calls") or []):
            fn = tc.get("function", {})
            tool_calls.append(ToolCall(
                id=f"call_{len(tool_calls)}",
                name=fn.get("name", ""),
                arguments=fn.get("arguments", {})
            ))

        return content, (tool_calls if tool_calls else None)
