import os
import difflib
from pathlib import Path
from typing import Dict, Any, Optional
from ..types import ToolDefinition, ToolResult
from .base import BaseTool

def _read_file_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        working_dir = context.get("working_directory", os.getcwd())
        file_path = (Path(working_dir) / params["path"]).resolve()

        if not file_path.exists():
            return ToolResult(success=False, output="", error=f"File not found: {params['path']}")

        content = file_path.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()

        start = int(params.get("startLine", 1))
        end = int(params.get("endLine", len(lines)))

        start = max(1, start)
        end = min(len(lines), end)

        selected = lines[start - 1:end]
        numbered = [f"{start + i}: {line}" for i, line in enumerate(selected)]

        return ToolResult(
            success=True,
            output=f"File: {params['path']} (Lines {start}-{end} of {len(lines)})\n\n" + "\n".join(numbered)
        )
    except Exception as e:
        return ToolResult(success=False, output="", error=str(e))

read_file_tool = BaseTool(
    definition=ToolDefinition(
        name="read_file",
        description="Read the contents of a text file from disk. Can read entire file or specific line ranges.",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative or absolute file path."},
                "startLine": {"type": "number", "description": "Optional 1-based start line."},
                "endLine": {"type": "number", "description": "Optional 1-based end line."}
            },
            "required": ["path"]
        }
    ),
    handler=_read_file_handler
)

def _write_file_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        working_dir = context.get("working_directory", os.getcwd())
        file_path = (Path(working_dir) / params["path"]).resolve()

        file_path.parent.mkdir(parents=True, exist_ok=True)
        content = params["content"]

        file_path.write_text(content, encoding="utf-8")
        return ToolResult(
            success=True,
            output=f"Successfully wrote {len(content.encode('utf-8'))} bytes to {params['path']}"
        )
    except Exception as e:
        return ToolResult(success=False, output="", error=str(e))

write_file_tool = BaseTool(
    definition=ToolDefinition(
        name="write_file",
        description="Write content to a file, completely creating or overwriting it.",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to write the file."},
                "content": {"type": "string", "description": "Full file content to write."}
            },
            "required": ["path", "content"]
        }
    ),
    handler=_write_file_handler
)

def _edit_file_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        working_dir = context.get("working_directory", os.getcwd())
        file_path = (Path(working_dir) / params["path"]).resolve()

        if not file_path.exists():
            return ToolResult(success=False, output="", error=f"File not found: {params['path']}")

        content = file_path.read_text(encoding="utf-8", errors="replace")
        target = params["target"]
        replacement = params["replacement"]

        if target not in content:
            return ToolResult(
                success=False,
                output="",
                error=f"Target string not found in {params['path']}. Verify exact whitespace."
            )

        new_content = content.replace(target, replacement, 1)
        file_path.write_text(new_content, encoding="utf-8")

        diff = "".join(difflib.unified_diff(
            content.splitlines(keepends=True),
            new_content.splitlines(keepends=True),
            fromfile=f"a/{params['path']}",
            tofile=f"b/{params['path']}"
        ))

        return ToolResult(
            success=True,
            output=f"Successfully edited {params['path']}\n\nDiff:\n{diff}"
        )
    except Exception as e:
        return ToolResult(success=False, output="", error=str(e))

edit_file_tool = BaseTool(
    definition=ToolDefinition(
        name="edit_file",
        description="Replace exact target string with replacement content in an existing file.",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to file to edit."},
                "target": {"type": "string", "description": "Exact text to replace."},
                "replacement": {"type": "string", "description": "Replacement text."}
            },
            "required": ["path", "target", "replacement"]
        }
    ),
    handler=_edit_file_handler
)
