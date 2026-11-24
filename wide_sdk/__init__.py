import importlib
import json
import urllib.request
from typing import Any, Dict, Tuple

__version__ = "0.8241126"

_EXPORTS: Dict[str, Tuple[str, str]] = {
    "CommitmentGate": (".decision", "CommitmentGate"),
    "Commitment": (".decision", "Commitment"),
    "PluralityConsensus": (".decision", "PluralityConsensus"),
    "ClaimTable": (".decision", "ClaimTable"),
    "PartitionAssignment": (".decision", "PartitionAssignment"),
    "WeightedScorer": (".decision", "WeightedScorer"),
    "Criterion": (".decision", "Criterion"),
    "SynchronizationBarrier": (".decision", "SynchronizationBarrier"),
    "BarrierBudget": (".decision", "BarrierBudget"),
    "ChatMessage": (".types", "ChatMessage"),
    "ToolCall": (".types", "ToolCall"),
    "ToolDefinition": (".types", "ToolDefinition"),
    "ToolResult": (".types", "ToolResult"),
    "Finding": (".types", "Finding"),
    "ScanResult": (".types", "ScanResult"),
    "ContextManager": (".context", "ContextManager"),
    "Agent": (".agent", "Agent"),
    "BaseTool": (".tools", "BaseTool"),
    "tool": (".tools", "tool"),
    "DEFAULT_TOOLS": (".tools", "DEFAULT_TOOLS"),
    "browser_navigate_tool": (".tools", "browser_navigate_tool"),
    "browser_click_tool": (".tools", "browser_click_tool"),
    "browser_type_tool": (".tools", "browser_type_tool"),
    "browser_extract_tool": (".tools", "browser_extract_tool"),
    "browser_screenshot_tool": (".tools", "browser_screenshot_tool"),
    "browser_close_tool": (".tools", "browser_close_tool"),
    "BrowserController": (".browser", "BrowserController"),
    "BrowserState": (".browser", "BrowserState"),
    "DOMElement": (".browser", "DOMElement"),
    "SecurityScanner": (".security", "SecurityScanner"),
    "SecurityRule": (".security", "SecurityRule"),
    "SECURITY_RULES": (".security", "SECURITY_RULES"),
    "DEFAULT_AGENT_RULES": (".security", "DEFAULT_AGENT_RULES"),
    "load_rules": (".security", "load_rules"),
    "load_agent_rules": (".security", "load_agent_rules"),
    "get_agent_rules_path": (".security", "get_agent_rules_path"),
    "SECURITY_PAYLOADS": (".security", "SECURITY_PAYLOADS"),
    "fuzz_endpoint": (".security", "fuzz_endpoint"),
    "get_payloads_for_type": (".security", "get_payloads_for_type"),
    "get_all_payload_types": (".security", "get_all_payload_types"),
    "DatabaseClient": (".database", "DatabaseClient"),
    "DatabaseConnectionSpec": (".database", "DatabaseConnectionSpec"),
    "QueryResult": (".database", "QueryResult"),
    "SchemaResult": (".database", "SchemaResult"),
    "SecurityAuditFinding": (".database", "SecurityAuditFinding"),
    "parse_database_target": (".database", "parse_database_target"),
    "mask_dsn": (".database", "mask_dsn"),
    "db_inspect_schema_tool": (".tools.db", "db_inspect_schema_tool"),
    "db_query_tool": (".tools.db", "db_query_tool"),
    "db_audit_tool": (".tools.db", "db_audit_tool"),
    "BaseProvider": (".providers", "BaseProvider"),
    "GeminiProvider": (".providers", "GeminiProvider"),
    "OllamaProvider": (".providers", "OllamaProvider"),
    "ClaudeProvider": (".providers", "ClaudeProvider"),
    "OpenAIProvider": (".providers", "OpenAIProvider"),
    "DeepSeekProvider": (".providers", "DeepSeekProvider"),
}


def __getattr__(name: str) -> Any:
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module 'wide_sdk' has no attribute {name!r}")
    mod_name, attr_name = target
    mod = importlib.import_module(mod_name, __name__)
    val = getattr(mod, attr_name)
    globals()[name] = val
    return val


def __dir__() -> list[str]:
    return sorted(list(globals().keys()) + list(__all__))


def check_for_updates() -> dict:
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
    "DatabaseClient",
    "DatabaseConnectionSpec",
    "QueryResult",
    "SchemaResult",
    "SecurityAuditFinding",
    "parse_database_target",
    "mask_dsn",
    "db_inspect_schema_tool",
    "db_query_tool",
    "db_audit_tool",
    "check_for_updates",
    "__version__",
]
