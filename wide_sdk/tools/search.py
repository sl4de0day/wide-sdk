import fnmatch
import os
import re
from pathlib import Path
from typing import Dict, Any, List
from ..types import ToolDefinition, ToolResult
from .base import BaseTool

_MAX_SEARCH_FILE_BYTES = 1024 * 1024
_IGNORE_DIRS = {"node_modules", ".git", "dist", "build", ".next", ".cache", "__pycache__", ".venv", "venv"}

def _list_dir_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        working_dir = context.get("working_directory", os.getcwd())
        target_path = (Path(working_dir) / params.get("path", ".")).resolve()
        if not target_path.exists() or not target_path.is_dir():
            return ToolResult(success=False, output="", error=f"Directory not found: {params.get('path', '.')}")
        max_depth = int(params.get("maxDepth", 1))

        entries: List[str] = []

        def traverse(current_dir: Path, depth: int) -> None:
            if depth > max_depth or not current_dir.exists():
                return
            for item in sorted(current_dir.iterdir()):
                if item.name in _IGNORE_DIRS:
                    continue
                rel = item.relative_to(target_path)
                if item.is_dir():
                    entries.append(f"[DIR]  {rel}/")
                    traverse(item, depth + 1)
                else:
                    try:
                        size = item.stat().st_size
                        entries.append(f"[FILE] {rel} ({size} B)")
                    except OSError:
                        entries.append(f"[FILE] {rel} (unreadable)")

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
        glob_filter = str(params.get("glob", "**/*") or "**/*").replace("\\", "/")

        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            return ToolResult(success=False, output="", error=f"Invalid search pattern: {exc}")

        matches: List[str] = []
        glob_pattern = glob_filter
        escaped = re.escape(glob_pattern)
        escaped = escaped.replace(r"\*\*/", "(?:.*/)?").replace(r"\*\*", ".*").replace(r"\*", "[^/]*").replace(r"\?", "[^/]")
        glob_re = re.compile(f"^{escaped}$")
        match_basename_only = "/" not in glob_pattern

        for root, dirs, files in os.walk(root_path):
            dirs[:] = sorted(d for d in dirs if d not in _IGNORE_DIRS)
            for fname in sorted(files):
                item = Path(root) / fname
                rel = item.relative_to(root_path)
                rel_posix = rel.as_posix()
                matched = bool(glob_re.match(fname if match_basename_only else rel_posix))
                if not matched:
                    continue

                try:
                    if item.stat().st_size > _MAX_SEARCH_FILE_BYTES:
                        continue
                    raw = item.read_bytes()
                    if b"\x00" in raw[:2048]:
                        continue
                    content = raw.decode("utf-8", errors="ignore")
                    lines = content.splitlines()

                    for idx, line in enumerate(lines):
                        if len(line) > 2000:
                            continue
                        if regex.search(line):
                            matches.append(f"{rel}:{idx + 1}: {line.strip()}")
                            if len(matches) >= 100:
                                break
                except Exception:
                    pass

                if len(matches) >= 100:
                    break
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
