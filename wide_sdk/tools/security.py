from typing import Dict, Any
from ..types import ToolDefinition, ToolResult
from ..security.scanner import SecurityScanner
from ..security.fuzzer import fuzz_endpoint
from ..security.payloads import get_payloads_for_type, get_all_payload_types
from .base import BaseTool

def _sec_scan_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        working_dir = context.get("working_directory", ".")
        scanner = SecurityScanner(working_dir)
        target_path = params.get("path", ".")
        min_sev = params.get("severityFilter", "ALL")
        result = scanner.scan(target_path, min_sev)
        return ToolResult(success=True, output=scanner.format_cli_report(result))
    except Exception as e:
        return ToolResult(success=False, output="", error=f"Security scan failed: {str(e)}")

run_security_scan_tool = BaseTool(
    definition=ToolDefinition(
        name="run_security_scan",
        description="Scan workspace code for security vulnerabilities, secrets, and injection flaws using Wide's native SAST engine.",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Target path to scan (default '.')."},
                "severityFilter": {"type": "string", "description": "Minimum severity.", "enum": ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]}
            },
            "required": []
        }
    ),
    handler=_sec_scan_handler
)

def _fuzz_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        report = fuzz_endpoint(
            url=params["url"],
            param=params["param"],
            payload_type=params["payloadType"],
            method=params.get("method", "GET")
        )
        lines = [
            f"Fuzzing Target: {report.url}",
            f"Tested Parameter: {report.param}",
            f"Payload Type: {report.payload_type.upper()}",
            f"Baseline HTTP: {report.baseline_status} ({report.baseline_length} bytes)",
            f"Verdict: {'[VULNERABLE]' if report.is_vulnerable else '[SAFE / NO ANOMALY]'}",
            f"Summary: {report.summary}\n"
        ]
        if report.findings:
            lines.append("Confirmed Findings:")
            for f in report.findings:
                lines.append(f"  Payload:   {f.payload}")
                lines.append(f"  Status:    {f.status_code}")
                lines.append(f"  Indicator: {f.indicator}\n")
        return ToolResult(success=True, output="\n".join(lines))
    except Exception as e:
        return ToolResult(success=False, output="", error=f"Fuzzing failed: {str(e)}")

fuzz_endpoint_tool = BaseTool(
    definition=ToolDefinition(
        name="fuzz_endpoint",
        description="Actively probe a web API endpoint parameter with security payloads to detect or verify vulnerabilities.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target endpoint URL."},
                "param": {"type": "string", "description": "Parameter to fuzz."},
                "payloadType": {"type": "string", "description": "Category of payloads.", "enum": ["sqli", "xss", "ssrf", "traversal", "cmd", "ssti"]},
                "method": {"type": "string", "description": "HTTP method ('GET' or 'POST').", "enum": ["GET", "POST"]}
            },
            "required": ["url", "param", "payloadType"]
        }
    ),
    handler=_fuzz_handler
)

def _gen_payloads_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    ptype = params.get("type", "")
    list_p = get_payloads_for_type(ptype)
    if not list_p:
        return ToolResult(success=False, output="", error=f"Unknown category '{ptype}'. Available: {', '.join(get_all_payload_types())}")

    formatted = [f"{i + 1}. {p}" for i, p in enumerate(list_p)]
    return ToolResult(success=True, output=f"Wide Security Payloads ({ptype.upper()}):\n\n" + "\n".join(formatted))

generate_payloads_tool = BaseTool(
    definition=ToolDefinition(
        name="generate_payloads",
        description="Generate targeted security test vectors and injection strings for penetration testing.",
        parameters={
            "type": "object",
            "properties": {
                "type": {"type": "string", "description": "Category of payloads.", "enum": ["sqli", "xss", "ssrf", "traversal", "cmd", "ssti"]}
            },
            "required": ["type"]
        }
    ),
    handler=_gen_payloads_handler
)
