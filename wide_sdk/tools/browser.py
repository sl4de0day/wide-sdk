from typing import Dict, Any, Optional
from ..types import ToolDefinition, ToolResult
from ..browser.controller import BrowserController
from .base import BaseTool

_active_browser: Optional[BrowserController] = None

def get_browser() -> BrowserController:
    global _active_browser
    if _active_browser is None:
        _active_browser = BrowserController(headless=True)
    return _active_browser

def _browser_navigate_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        url = params["url"]
        browser = get_browser()
        result = browser.navigate(url)
        return ToolResult(success=True, output=result)
    except Exception as e:
        return ToolResult(success=False, output="", error=f"Navigation error: {str(e)}")

browser_navigate_tool = BaseTool(
    definition=ToolDefinition(
        name="browser_navigate",
        description="Navigate the autonomous browser to a target URL. Returns page title, status, and numbered interactive elements.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The destination URL to open (e.g. https://example.com)."}
            },
            "required": ["url"]
        }
    ),
    handler=_browser_navigate_handler
)

def _browser_click_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        target = params["target"]
        browser = get_browser()
        result = browser.click(target)
        return ToolResult(success=True, output=result)
    except Exception as e:
        return ToolResult(success=False, output="", error=f"Click error: {str(e)}")

browser_click_tool = BaseTool(
    definition=ToolDefinition(
        name="browser_click",
        description="Click an interactive element (link, button, tab) on the current page by its index (e.g. '[1]') or text label.",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Element index (e.g. '[3]' or '3') or text label to click."}
            },
            "required": ["target"]
        }
    ),
    handler=_browser_click_handler
)

def _browser_type_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        target = params["target"]
        text = params["text"]
        submit = bool(params.get("submit", False))
        browser = get_browser()
        result = browser.fill(target, text, submit=submit)
        return ToolResult(success=True, output=result)
    except Exception as e:
        return ToolResult(success=False, output="", error=f"Type error: {str(e)}")

browser_type_tool = BaseTool(
    definition=ToolDefinition(
        name="browser_type",
        description="Type text into an input field or textarea identified by its index (e.g. '[2]') or name/placeholder.",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Element index (e.g. '[2]') or input name/placeholder."},
                "text": {"type": "string", "description": "Text to fill into the input field."},
                "submit": {"type": "boolean", "description": "Optional boolean to submit the form after typing (default false)."}
            },
            "required": ["target", "text"]
        }
    ),
    handler=_browser_type_handler
)

def _browser_extract_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        query = params.get("query", "")
        browser = get_browser()
        result = browser.extract(query)
        return ToolResult(success=True, output=result)
    except Exception as e:
        return ToolResult(success=False, output="", error=f"Extract error: {str(e)}")

browser_extract_tool = BaseTool(
    definition=ToolDefinition(
        name="browser_extract",
        description="Extract visible text content or query-matched information from the currently loaded webpage.",
        parameters={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Optional keyword or phrase to filter extracted text content."}
            }
        }
    ),
    handler=_browser_extract_handler
)

def _browser_screenshot_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        browser = get_browser()
        result = browser.screenshot()
        return ToolResult(success=True, output=result)
    except Exception as e:
        return ToolResult(success=False, output="", error=f"Screenshot error: {str(e)}")

browser_screenshot_tool = BaseTool(
    definition=ToolDefinition(
        name="browser_screenshot",
        description="Capture a structured viewport snapshot of the current browser page, displaying status, URL, and interactive elements.",
        parameters={
            "type": "object",
            "properties": {}
        }
    ),
    handler=_browser_screenshot_handler
)

def _browser_close_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        browser = get_browser()
        result = browser.close()
        return ToolResult(success=True, output=result)
    except Exception as e:
        return ToolResult(success=False, output="", error=f"Close error: {str(e)}")

browser_close_tool = BaseTool(
    definition=ToolDefinition(
        name="browser_close",
        description="Close the active browser session and reset browsing history.",
        parameters={
            "type": "object",
            "properties": {}
        }
    ),
    handler=_browser_close_handler
)
