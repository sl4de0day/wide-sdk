import time
import urllib.request
import urllib.error
from typing import Dict, Any
from ..types import ToolDefinition, ToolResult
from .base import BaseTool

def _http_request_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    url = params["url"]
    method = params.get("method", "GET").upper()
    timeout = int(params.get("timeoutMs", 15000)) / 1000.0
    headers = params.get("headers", {})
    body = params.get("body")

    data_bytes = body.encode("utf-8") if body and method not in ("GET", "HEAD") else None

    req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
    start_time = time.time()

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            duration_ms = int((time.time() - start_time) * 1000)
            res_body = response.read().decode("utf-8", errors="replace")

            if len(res_body) > 8000:
                res_body = res_body[:8000] + "\n... [Body truncated]"

            res_headers = [f"{k}: {v}" for k, v in response.getheaders()]

            output = [
                f"Status: {response.status} {response.reason}",
                f"Duration: {duration_ms}ms",
                f"Headers:\n" + "\n".join(res_headers),
                f"Body:\n{res_body or '[Empty Body]'}"
            ]
            return ToolResult(success=True, output="\n\n".join(output))
    except urllib.error.HTTPError as e:
        duration_ms = int((time.time() - start_time) * 1000)
        res_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        output = [
            f"Status: {e.code} {e.reason}",
            f"Duration: {duration_ms}ms",
            f"Body:\n{res_body or '[Empty Body]'}"
        ]
        return ToolResult(success=True, output="\n\n".join(output))
    except Exception as e:
        return ToolResult(success=False, output="", error=f"HTTP request failed: {str(e)}")

send_http_request_tool = BaseTool(
    definition=ToolDefinition(
        name="send_http_request",
        description="Send an HTTP/HTTPS request to test an API endpoint or verify security patches.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target endpoint URL."},
                "method": {"type": "string", "description": "HTTP method.", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]},
                "headers": {"type": "object", "description": "Optional request headers dictionary."},
                "body": {"type": "string", "description": "Optional request payload."},
                "timeoutMs": {"type": "number", "description": "Timeout in milliseconds (default 15000)."}
            },
            "required": ["url"]
        }
    ),
    handler=_http_request_handler
)
