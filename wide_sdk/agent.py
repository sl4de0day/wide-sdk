import os
import json
import re
from typing import List, Dict, Optional, Callable, Any
from .types import ChatMessage, ToolDefinition, ToolCall, ToolResult
from .context import ContextManager
from .providers.base import BaseProvider
from .tools.base import BaseTool
from .tools import DEFAULT_TOOLS
from .decision import CommitmentGate
from .security.loader import RuleLoader
from .security.rules import SecurityRule

DEFAULT_SYSTEM_PROMPT = """You are Wide Agent, an autonomous security-first AI coding and penetration testing assistant.
You operate programmatically via Wide SDK.

Your capabilities:
- Read, write, and edit code files autonomously with precision diffs.
- Run terminal commands to test, compile, or audit software.
- Run Wide's native SAST engine (run_security_scan) across 20+ vulnerability classes (SQLi, XSS, SSRF, Command Injection, XXE, Deserialization, Hardcoded Secrets, IDOR, Path Traversal, CORS, CSRF, ReDoS).
- Send HTTP requests (send_http_request) to probe web endpoints and verify vulnerability remediations.
- Fuzz web endpoints (fuzz_endpoint) with automated injection vectors to verify live vulnerabilities.
- Generate targeted offensive security payloads (generate_payloads) for penetration testing.
- Autonomously navigate, interact with, click, fill forms, and extract content from websites using browser tools (browser_navigate, browser_click, browser_type, browser_extract, browser_screenshot, browser_close).
- Keep your answers concise, practical, and action-oriented.
- Do not use emojis anywhere in your responses or generated code. Never output emojis under any circumstances.
- Always inspect relevant files before modifying them.
- When fixing security vulnerabilities, provide clean, secure, production-grade solutions."""

class Agent:
    def __init__(
        self,
        provider: BaseProvider,
        working_directory: str = ".",
        system_prompt: Optional[str] = None,
        tools: Optional[Dict[str, BaseTool]] = None,
        max_iterations: int = 25,
        on_thought: Optional[Callable[[str], None]] = None,
        on_tool_call: Optional[Callable[[ToolCall], None]] = None,
        on_tool_result: Optional[Callable[[str, ToolResult], None]] = None
    ) -> None:
        self.provider = provider
        self.working_directory = os.path.abspath(working_directory)
        self.system_prompt = system_prompt or DEFAULT_SYSTEM_PROMPT
        self.tools = dict(tools or DEFAULT_TOOLS)
        self.max_iterations = max_iterations
        self.context_manager = ContextManager()
        self.on_thought = on_thought
        self.on_tool_call = on_tool_call
        self.on_tool_result = on_tool_result
        self.agent_rules = RuleLoader.load_agent_rules(workspace_dir=self.working_directory)

        self.messages: List[ChatMessage] = [
            ChatMessage(role="system", content=self.system_prompt)
        ]

    def get_agent_rules(self) -> List[SecurityRule]:
        return self.agent_rules

    def reload_agent_rules(self) -> List[SecurityRule]:
        self.agent_rules = RuleLoader.load_agent_rules(workspace_dir=self.working_directory)
        return self.agent_rules

    def register_tool(self, tool: BaseTool) -> None:
        self.tools[tool.definition.name] = tool

    def clear_history(self) -> None:
        self.messages = [
            ChatMessage(role="system", content=self.system_prompt)
        ]

    def run(self, user_prompt: str) -> str:
        self.messages.append(ChatMessage(role="user", content=user_prompt))
        tool_defs = [t.definition for t in self.tools.values()]

        iteration = 0
        final_text = ""
        gate = CommitmentGate(32, 0.0)
        call_counts: Dict[str, int] = {}

        while iteration < self.max_iterations:
            iteration += 1
            self.messages = self.context_manager.compact_messages(self.messages)

            content, tool_calls = self.provider.chat(self.messages, tool_defs)
            if content:
                content = re.sub(r"[\U00010000-\U0010ffff\u2600-\u26ff\u2700-\u27bf\u2300-\u23ff]", "", content)
            final_text = content

            if content and self.on_thought:
                self.on_thought(content)

            self.messages.append(ChatMessage(
                role="assistant",
                content=content,
                tool_calls=tool_calls
            ))

            if not tool_calls:
                break

            for tc in tool_calls:
                if self.on_tool_call:
                    self.on_tool_call(tc)

                sig = f"{tc.name}:{json.dumps(tc.arguments, sort_keys=True)}"
                count = call_counts.get(sig, 0) + 1
                call_counts[sig] = count

                if count > 3:
                    result = ToolResult(
                        success=False,
                        output="",
                        error="DecisionCore CommitmentGate suppressed duplicate tool execution. Please synthesize your findings and answer or select an alternative tool."
                    )
                    self.messages.append(ChatMessage(
                        role="tool",
                        name=tc.name,
                        tool_call_id=tc.id,
                        content=result.error
                    ))
                    if self.on_tool_result:
                        self.on_tool_result(tc.name, result)
                    continue

                tool = self.tools.get(tc.name)
                if not tool:
                    result = ToolResult(
                        success=False,
                        output="",
                        error=f"Unknown tool '{tc.name}'. Available: {', '.join(self.tools.keys())}"
                    )
                else:
                    try:
                        ctx = {"working_directory": self.working_directory}
                        result = tool.execute(tc.arguments, ctx)
                    except Exception as e:
                        result = ToolResult(success=False, output="", error=str(e))

                if self.on_tool_result:
                    self.on_tool_result(tc.name, result)

                output_str = result.output if result.success else f"ERROR: {result.error}"
                self.messages.append(ChatMessage(
                    role="tool",
                    name=tc.name,
                    tool_call_id=tc.id,
                    content=output_str
                ))

        return final_text
