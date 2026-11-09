import os
import re
from pathlib import Path
from typing import Dict, Any, List
from ..types import ToolDefinition, ToolResult
from .base import BaseTool

def _list_dir_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        working_dir = context.get("working_directory", os.getcwd())
        target_path = (Path(working_dir) / params.get("path", ".")).resolve()
        max_depth = int(params.get("maxDepth", 1))

        ignore_dirs = {"node_modules", ".git", "dist", "build", ".next", ".cache", "__pycache__", ".venv", "venv"}
        entries: List[str] = []

        def traverse(current_dir: Path, depth: int) -> None:
            if depth > max_depth or not current_dir.exists():
                return
            for item in sorted(current_dir.iterdir()):
                if item.name in ignore_dirs:
                    continue
                rel = item.relative_to(target_path)
                if item.is_dir():
                    entries.append(f"[DIR]  {rel}/")
                    traverse(item, depth + 1)
                else:
                    size = item.stat().st_size
                    entries.append(f"[FILE] {rel} ({size} B)")

        traverse(target_path, 1)
        output = "\n".join(entries[:200])
        if len(entries) > 200:
            output += f"\n... ({len(entries) - 200} more items)"

        return ToolResult(success=True, output=output)
    except Exception as e:
        return ToolResult(success=False, output="", error=str(e))

list_dir_tool = BaseTool(
    definition=ToolDefinition(
        name="list_dir",
        description="List files and directories in a given folder with file sizes.",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Folder path relative to workspace."},
                "maxDepth": {"type": "number", "description": "Maximum recursion depth (default 1)."}
            },
            "required": []
        }
    ),
    handler=_list_dir_handler
)

def _search_files_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        working_dir = context.get("working_directory", os.getcwd())
        root_path = Path(working_dir).resolve()
        pattern = params["pattern"]
        glob_filter = params.get("glob", "**/*")

        regex = re.compile(pattern, re.IGNORECASE)
        ignore_dirs = {"node_modules", ".git", "dist", "build", ".cache", "__pycache__", ".venv", "venv"}

        matches: List[str] = []

        for item in root_path.glob(glob_filter):
            if any(part in ignore_dirs for part in item.parts):
                continue
            if not item.is_file():
                continue

            try:
                content = item.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()
                rel = item.relative_to(root_path)

                for idx, line in enumerate(lines):
                    if regex.search(line):
                        matches.append(f"{rel}:{idx + 1}: {line.strip()}")
                        if len(matches) >= 100:
                            break
            except Exception:
                pass

            if len(matches) >= 100:
                break

        if not matches:
            return ToolResult(success=True, output=f"No matches found for '{pattern}'.")

        return ToolResult(
            success=True,
            output=f"Found {len(matches)} matches:\n\n" + "\n".join(matches)
        )
    except Exception as e:
        return ToolResult(success=False, output="", error=str(e))

search_files_tool = BaseTool(
    definition=ToolDefinition(
        name="search_files",
        description="Search for a regex or string pattern inside files matching an optional glob filter.",
        parameters={
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Text or regex to search."},
                "glob": {"type": "string", "description": "Optional glob filter (default '**/*')."}
            },
            "required": ["pattern"]
        }
    ),
    handler=_search_files_handler
)
