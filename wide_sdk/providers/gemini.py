import os
import json
import urllib.request
import urllib.error
from typing import List, Tuple, Optional
from ..types import ChatMessage, ToolDefinition, ToolCall
from .base import BaseProvider

class GeminiProvider(BaseProvider):
    name = "gemini"

    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-2.5-flash") -> None:
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self.model = model
        if not self.api_key:
            raise ValueError("Gemini API key is required. Set GEMINI_API_KEY environment variable or pass api_key.")

    def chat(
        self,
        messages: List[ChatMessage],
        tools: List[ToolDefinition]
    ) -> Tuple[str, Optional[List[ToolCall]]]:
        system_msg = next((m for m in messages if m.role == "system"), None)
        chat_msgs = [m for m in messages if m.role != "system"]

        contents = []
        for m in chat_msgs:
            if m.role == "user":
                contents.append({"role": "user", "parts": [{"text": m.content}]})
            elif m.role == "assistant":
                parts = []
                if m.content:
                    parts.append({"text": m.content})
                if m.tool_calls:
                    for tc in m.tool_calls:
                        parts.append({"functionCall": {"name": tc.name, "args": tc.arguments}})
                contents.append({"role": "model", "parts": parts})
            elif m.role == "tool":
                contents.append({
                    "role": "user",
                    "parts": [{"functionResponse": {"name": m.name or "tool_result", "response": {"output": m.content}}}]
                })

        function_declarations = [
            {
                "name": t.name,
                "description": t.description,
                "parameters": {
                    "type": "OBJECT",
                    "properties": t.parameters.get("properties", {}),
                    "required": t.parameters.get("required", [])
                }
            }
            for t in tools
        ]

        payload = {
            "contents": contents,
            "generationConfig": {"temperature": 0.2}
        }

        if system_msg:
            payload["systemInstruction"] = {"parts": [{"text": system_msg.content}]}
        if function_declarations:
            payload["tools"] = [{"functionDeclarations": function_declarations}]

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=60.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_msg = e.read().decode("utf-8") if e.fp else str(e)
            raise RuntimeError(f"Gemini API error ({e.code}): {err_msg}")

        candidate = data.get("candidates", [{}])[0]
        parts = candidate.get("content", {}).get("parts", [])

        full_text = ""
        tool_calls: List[ToolCall] = []

        for p in parts:
            if "text" in p:
                full_text += p["text"]
            if "functionCall" in p:
                fc = p["functionCall"]
                tool_calls.append(ToolCall(
                    id=f"call_{len(tool_calls)}",
                    name=fc["name"],
                    arguments=fc.get("args", {})
                ))

        return full_text, (tool_calls if tool_calls else None)
