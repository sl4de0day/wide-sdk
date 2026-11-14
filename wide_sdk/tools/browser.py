from typing import Any, Dict, Optional
from ..browser.controller import BrowserController
from ..types import ToolDefinition, ToolResult
from .base import BaseTool

_active_browser: Optional[BrowserController] = None


def get_browser() -> BrowserController:
    global _active_browser
    if _active_browser is None:
        _active_browser = BrowserController(headless=True)
    return _active_browser


def _browser_open_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        browser = get_browser()
        result = browser.open(params.get("url"))
        return ToolResult(success=True, output=result)
    except Exception as e:
        return ToolResult(success=False, output="", error=f"Open error: {str(e)}")


browser_open_tool = BaseTool(
    definition=ToolDefinition(
        name="browser_open",
        description="Initialize the real Chromium/Edge browser session and optionally open a URL.",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Optional destination URL to open immediately."}
            }
        }
    ),
    handler=_browser_open_handler
)


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
        description="Navigate the autonomous browser to a target URL. Returns page title, status, and @eN / [N] interactive elements.",
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


def _browser_snapshot_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        browser = get_browser()
        result = browser.snapshot()
        return ToolResult(success=True, output=result)
    except Exception as e:
        return ToolResult(success=False, output="", error=f"Snapshot error: {str(e)}")


browser_snapshot_tool = BaseTool(
    definition=ToolDefinition(
        name="browser_snapshot",
        description="Capture a fresh interactive DOM snapshot with @eN element refs and visible text.",
        parameters={"type": "object", "properties": {}}
    ),
    handler=_browser_snapshot_handler
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
        description="Click an interactive element (link, button, tab) by its @eN ref, [N] index, CSS selector, or text label.",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Element ref ('@e3'), index ('[3]'), CSS selector, or text label."}
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
        description="Type text into an input field or textarea identified by @eN ref, [N] index, CSS selector, or name/placeholder.",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Element ref ('@e2'), index ('[2]'), CSS selector, or input name/placeholder."},
                "text": {"type": "string", "description": "Text to fill into the input field."},
                "submit": {"type": "boolean", "description": "Optional boolean to submit the form after typing (default false)."}
            },
            "required": ["target", "text"]
        }
    ),
    handler=_browser_type_handler
)


def _browser_press_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        browser = get_browser()
        result = browser.press(params["key"])
        return ToolResult(success=True, output=result)
    except Exception as e:
        return ToolResult(success=False, output="", error=f"Key press error: {str(e)}")


browser_press_tool = BaseTool(
    definition=ToolDefinition(
        name="browser_press",
        description="Dispatch a keyboard key press (Enter, Tab, Escape, ArrowDown) in the active browser page.",
        parameters={
            "type": "object",
            "properties": {
                "key": {"type": "string", "description": "Key name to press."}
            },
            "required": ["key"]
        }
    ),
    handler=_browser_press_handler
)


def _browser_hover_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        browser = get_browser()
        result = browser.hover(params["target"])
        return ToolResult(success=True, output=result)
    except Exception as e:
        return ToolResult(success=False, output="", error=f"Hover error: {str(e)}")


browser_hover_tool = BaseTool(
    definition=ToolDefinition(
        name="browser_hover",
        description="Hover the pointer over an element identified by @eN ref, index, or CSS selector.",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Element ref, index, or CSS selector."}
            },
            "required": ["target"]
        }
    ),
    handler=_browser_hover_handler
)


def _browser_select_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        browser = get_browser()
        result = browser.select(params["target"], params["value"])
        return ToolResult(success=True, output=result)
    except Exception as e:
        return ToolResult(success=False, output="", error=f"Select error: {str(e)}")


browser_select_tool = BaseTool(
    definition=ToolDefinition(
        name="browser_select",
        description="Select an option value on a <select> dropdown element.",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Select element @eN ref, index, or CSS selector."},
                "value": {"type": "string", "description": "Option value to select."}
            },
            "required": ["target", "value"]
        }
    ),
    handler=_browser_select_handler
)


def _browser_scroll_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        browser = get_browser()
        result = browser.scroll(params.get("direction", "down"), int(params.get("pixels", 500)))
        return ToolResult(success=True, output=result)
    except Exception as e:
        return ToolResult(success=False, output="", error=f"Scroll error: {str(e)}")


browser_scroll_tool = BaseTool(
    definition=ToolDefinition(
        name="browser_scroll",
        description="Scroll the browser viewport up, down, top, or bottom.",
        parameters={
            "type": "object",
            "properties": {
                "direction": {"type": "string", "enum": ["up", "down", "top", "bottom"], "description": "Scroll direction."},
                "pixels": {"type": "number", "description": "Scroll distance in pixels (default 500)."}
            }
        }
    ),
    handler=_browser_scroll_handler
)


def _browser_wait_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        browser = get_browser()
        result = browser.wait(
            ms=int(params.get("ms", 1000)),
            selector=params.get("selector", ""),
            text=params.get("text", "")
        )
        return ToolResult(success=True, output=result)
    except Exception as e:
        return ToolResult(success=False, output="", error=f"Wait error: {str(e)}")


browser_wait_tool = BaseTool(
    definition=ToolDefinition(
        name="browser_wait",
        description="Wait for a CSS selector, visible text, or fixed duration in the browser.",
        parameters={
            "type": "object",
            "properties": {
                "ms": {"type": "number", "description": "Timeout or delay in milliseconds."},
                "selector": {"type": "string", "description": "Optional CSS selector to wait for."},
                "text": {"type": "string", "description": "Optional visible text to wait for."}
            }
        }
    ),
    handler=_browser_wait_handler
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
        output_dir = context.get("working_directory") if context else None
        browser.capture_screenshot_file(output_dir)
        result = browser.screenshot()
        return ToolResult(success=True, output=result)
    except Exception as e:
        return ToolResult(success=False, output="", error=f"Screenshot error: {str(e)}")


browser_screenshot_tool = BaseTool(
    definition=ToolDefinition(
        name="browser_screenshot",
        description="Capture a screenshot PNG (when Chromium/Edge is active) and structured viewport snapshot.",
        parameters={"type": "object", "properties": {}}
    ),
    handler=_browser_screenshot_handler
)


def _browser_console_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        browser = get_browser()
        result = browser.console(clear=bool(params.get("clear", False)))
        return ToolResult(success=True, output=result)
    except Exception as e:
        return ToolResult(success=False, output="", error=f"Console error: {str(e)}")


browser_console_tool = BaseTool(
    definition=ToolDefinition(
        name="browser_console",
        description="Read console logs and runtime errors emitted by the active browser page.",
        parameters={
            "type": "object",
            "properties": {
                "clear": {"type": "boolean", "description": "Clear console logs after reading."}
            }
        }
    ),
    handler=_browser_console_handler
)


def _browser_cookies_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        browser = get_browser()
        result = browser.cookies(
            action=params.get("action", "get"),
            name=params.get("name", ""),
            value=str(params.get("value", "")),
            url=params.get("url", "")
        )
        return ToolResult(success=True, output=result)
    except Exception as e:
        return ToolResult(success=False, output="", error=f"Cookies error: {str(e)}")


browser_cookies_tool = BaseTool(
    definition=ToolDefinition(
        name="browser_cookies",
        description="Inspect, set, or clear browser cookies.",
        parameters={
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["get", "set", "clear"], "description": "Cookie operation."},
                "name": {"type": "string", "description": "Cookie name (for 'set')."},
                "value": {"type": "string", "description": "Cookie value (for 'set')."},
                "url": {"type": "string", "description": "Optional cookie URL (for 'set')."}
            }
        }
    ),
    handler=_browser_cookies_handler
)


def _browser_eval_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    try:
        browser = get_browser()
        result = browser.eval_js(params["script"])
        return ToolResult(success=True, output=result)
    except Exception as e:
        return ToolResult(success=False, output="", error=f"Eval error: {str(e)}")


browser_eval_tool = BaseTool(
    definition=ToolDefinition(
        name="browser_eval",
        description="Execute JavaScript in the active browser page context and return the serialized result.",
        parameters={
            "type": "object",
            "properties": {
                "script": {"type": "string", "description": "JavaScript expression or IIFE to evaluate."}
            },
            "required": ["script"]
        }
    ),
    handler=_browser_eval_handler
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
        parameters={"type": "object", "properties": {}}
    ),
    handler=_browser_close_handler
)
