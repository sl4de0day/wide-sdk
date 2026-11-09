import os
import subprocess
from typing import Dict, Any
from ..types import ToolDefinition, ToolResult
from .base import BaseTool

def _run_command_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    cmd = params["command"]
    timeout = int(params.get("timeoutMs", 30000)) / 1000.0
    working_dir = context.get("working_directory", os.getcwd())

    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            cwd=working_dir,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        if len(stdout) > 8000:
            stdout = stdout[:8000] + "\n... [Output truncated]"
        if len(stderr) > 4000:
            stderr = stderr[:4000] + "\n... [Stderr truncated]"

        combined = []
        if stdout:
            combined.append(f"Stdout:\n{stdout}")
        if stderr:
            combined.append(f"Stderr:\n{stderr}")
        combined.append(f"Exit Code: {proc.returncode}")

        return ToolResult(
            success=(proc.returncode == 0),
            output="\n\n".join(combined),
            error=stderr if proc.returncode != 0 else None
        )
    except subprocess.TimeoutExpired:
        return ToolResult(success=False, output="", error=f"Command timed out after {timeout} seconds")
    except Exception as e:
        return ToolResult(success=False, output="", error=str(e))

run_command_tool = BaseTool(
    definition=ToolDefinition(
        name="run_command",
        description="Execute a shell command in the project directory and return stdout/stderr.",
        parameters={
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to run."},
                "timeoutMs": {"type": "number", "description": "Optional timeout in milliseconds."}
            },
            "required": ["command"]
        }
    ),
    handler=_run_command_handler
)
