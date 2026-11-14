from .decision import (
    CommitmentGate,
    Commitment,
    PluralityConsensus,
    ClaimTable,
    PartitionAssignment,
    WeightedScorer,
    Criterion,
    SynchronizationBarrier,
    BarrierBudget,
)
from .types import (
    ChatMessage,
    ToolCall,
    ToolDefinition,
    ToolResult,
    Finding,
    ScanResult,
)
from .context import ContextManager
from .agent import Agent
from .tools import (
    BaseTool,
    tool,
    DEFAULT_TOOLS,
    browser_navigate_tool,
    browser_click_tool,
    browser_type_tool,
    browser_extract_tool,
    browser_screenshot_tool,
    browser_close_tool,
)
from .browser import (
    BrowserController,
    BrowserState,
    DOMElement,
)
from .security import (
    SecurityScanner,
    SecurityRule,
    SECURITY_RULES,
    DEFAULT_AGENT_RULES,
    load_rules,
    load_agent_rules,
    get_agent_rules_path,
    SECURITY_PAYLOADS,
    fuzz_endpoint,
    get_payloads_for_type,
    get_all_payload_types,
)
from .providers import (
    BaseProvider,
    GeminiProvider,
    OllamaProvider,
    ClaudeProvider,
    OpenAIProvider,
    DeepSeekProvider,
)

__version__ = "0.3101126"

def check_for_updates() -> dict:
    import urllib.request
    import json
    url = "https://api.github.com/repos/sl4de0day/wide-sdk/releases/latest"
    req = urllib.request.Request(url, headers={"User-Agent": "Wide-SDK"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            latest = str(data.get("tag_name") or data.get("name") or "").lstrip("v")
            return {
                "current": __version__,
                "latest": latest,
                "available": latest > __version__ if latest else False,
            }
    except Exception as e:
        return {"current": __version__, "latest": "", "available": False, "error": str(e)}

__all__ = [
    "Agent",
    "CommitmentGate",
    "Commitment",
    "PluralityConsensus",
    "ClaimTable",
    "PartitionAssignment",
    "WeightedScorer",
    "Criterion",
    "SynchronizationBarrier",
    "BarrierBudget",
    "ContextManager",
    "SecurityScanner",
    "SecurityRule",
    "SECURITY_RULES",
    "DEFAULT_AGENT_RULES",
    "load_rules",
    "load_agent_rules",
    "get_agent_rules_path",
    "SECURITY_PAYLOADS",
    "BaseTool",
    "tool",
    "DEFAULT_TOOLS",
    "BrowserController",
    "BrowserState",
    "DOMElement",
    "browser_navigate_tool",
    "browser_click_tool",
    "browser_type_tool",
    "browser_extract_tool",
    "browser_screenshot_tool",
    "browser_close_tool",
    "BaseProvider",
    "GeminiProvider",
    "OllamaProvider",
    "ClaudeProvider",
    "OpenAIProvider",
    "DeepSeekProvider",
    "ChatMessage",
    "ToolCall",
    "ToolDefinition",
    "ToolResult",
    "Finding",
    "ScanResult",
    "fuzz_endpoint",
    "get_payloads_for_type",
    "get_all_payload_types",
    "check_for_updates",
    "__version__",
]
