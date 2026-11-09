from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Literal

@dataclass
class ToolCall:
    id: str
    name: str
    arguments: Dict[str, Any]

@dataclass
class ChatMessage:
    role: Literal["system", "user", "assistant", "tool"]
    content: str
    tool_calls: Optional[List[ToolCall]] = None
    tool_call_id: Optional[str] = None
    name: Optional[str] = None

@dataclass
class ToolDefinition:
    name: str
    description: str
    parameters: Dict[str, Any]

@dataclass
class ToolResult:
    success: bool
    output: str
    error: Optional[str] = None

@dataclass
class Finding:
    id: str
    cwe: str
    category: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    file: str
    line: int
    snippet: str
    message: str
    remediation: str

@dataclass
class ScanResult:
    total_files_scanned: int
    findings: List[Finding]
    summary: Dict[str, int]
