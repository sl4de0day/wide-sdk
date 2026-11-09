import os
import json
import urllib.request
import urllib.error
from typing import List, Tuple, Optional
from ..types import ChatMessage, ToolDefinition, ToolCall
from .base import BaseProvider

class OpenAICompatibleProvider(BaseProvider):
    def __init__(
        self,
        name: str = "openai",
        api_key: Optional[str] = None,
        model: str = "gpt-4o",
        base_url: str = "https://api.openai.com/v1"
    ) -> None:
        self.name = name
        env_var = f"{name.upper()}_API_KEY"
        self.api_key = api_key or os.environ.get(env_var, "") or os.environ.get("OPENAI_API_KEY", "")
        self.model = model
        self.base_url = base_url.rstrip("/")
        if not self.api_key:
            raise ValueError(f"{name.upper()} API key is required. Set {env_var} or pass api_key.")

    def chat(
        self,
        messages: List[ChatMessage],
        tools: List[ToolDefinition]
    ) -> Tuple[str, Optional[List[ToolCall]]]:
        formatted_messages = []
        for m in messages:
            if m.role == "tool":
                formatted_messages.append({
                    "role": "tool",
                    "tool_call_id": m.tool_call_id or "call_0",
                    "content": m.content
                })
            elif m.role == "assistant" and m.tool_calls:
                formatted_messages.append({
                    "role": "assistant",
                    "content": m.content or None,
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.name,
                                "arguments": json.dumps(tc.arguments)
                            }
                        }
                        for tc in m.tool_calls
                    ]
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
            "temperature": 0.2
        }
        if formatted_tools:
            payload["tools"] = formatted_tools

        url = f"{self.base_url}/chat/completions"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            },
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=60.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_msg = e.read().decode("utf-8") if e.fp else str(e)
            raise RuntimeError(f"{self.name} API error ({e.code}): {err_msg}")

        choice = data.get("choices", [{}])[0]
        msg = choice.get("message", {})
        content = msg.get("content") or ""
        tool_calls: List[ToolCall] = []

        if "tool_calls" in msg:
            for tc in msg["tool_calls"]:
                fn = tc.get("function", {})
                args = {}
                try:
                    args = json.loads(fn.get("arguments", "{}"))
                except Exception:
                    pass
                tool_calls.append(ToolCall(
                    id=tc.get("id", f"call_{len(tool_calls)}"),
                    name=fn.get("name", ""),
                    arguments=args
                ))

        return content, (tool_calls if tool_calls else None)

class OpenAIProvider(OpenAICompatibleProvider):
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o") -> None:
        super().__init__(name="openai", api_key=api_key, model=model, base_url="https://api.openai.com/v1")

class DeepSeekProvider(OpenAICompatibleProvider):
    def __init__(self, api_key: Optional[str] = None, model: str = "deepseek-chat") -> None:
        super().__init__(name="deepseek", api_key=api_key, model=model, base_url="https://api.deepseek.com/v1")
