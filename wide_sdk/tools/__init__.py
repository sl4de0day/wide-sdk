from .base import BaseTool, tool
from .fs import read_file_tool, write_file_tool, edit_file_tool
from .shell import run_command_tool
from .search import list_dir_tool, search_files_tool
from .http import send_http_request_tool
from .security import run_security_scan_tool, fuzz_endpoint_tool, generate_payloads_tool
from .browser import (
    browser_navigate_tool,
    browser_click_tool,
    browser_type_tool,
    browser_extract_tool,
    browser_screenshot_tool,
    browser_close_tool,
)

DEFAULT_TOOLS = {
    "read_file": read_file_tool,
    "write_file": write_file_tool,
    "edit_file": edit_file_tool,
    "list_dir": list_dir_tool,
    "search_files": search_files_tool,
    "send_http_request": send_http_request_tool,
    "run_command": run_command_tool,
    "run_security_scan": run_security_scan_tool,
    "fuzz_endpoint": fuzz_endpoint_tool,
    "generate_payloads": generate_payloads_tool,
    "browser_navigate": browser_navigate_tool,
    "browser_click": browser_click_tool,
    "browser_type": browser_type_tool,
    "browser_extract": browser_extract_tool,
    "browser_screenshot": browser_screenshot_tool,
    "browser_close": browser_close_tool,
}

__all__ = [
    "BaseTool",
    "tool",
    "read_file_tool",
    "write_file_tool",
    "edit_file_tool",
    "list_dir_tool",
    "search_files_tool",
    "send_http_request_tool",
    "run_command_tool",
    "run_security_scan_tool",
    "fuzz_endpoint_tool",
    "generate_payloads_tool",
    "browser_navigate_tool",
    "browser_click_tool",
    "browser_type_tool",
    "browser_extract_tool",
    "browser_screenshot_tool",
    "browser_close_tool",
    "DEFAULT_TOOLS",
]
