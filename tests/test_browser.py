import unittest
from wide_sdk.browser import BrowserController, DOMElement
from wide_sdk.browser.controller import _PageHTMLParser, strip_browser_emojis
from wide_sdk.tools import DEFAULT_TOOLS
from wide_sdk.tools.browser import (
    browser_open_tool,
    browser_navigate_tool,
    browser_snapshot_tool,
    browser_click_tool,
    browser_type_tool,
    browser_press_tool,
    browser_hover_tool,
    browser_select_tool,
    browser_scroll_tool,
    browser_wait_tool,
    browser_extract_tool,
    browser_screenshot_tool,
    browser_console_tool,
    browser_cookies_tool,
    browser_eval_tool,
    browser_export_har_tool,
    browser_close_tool,
    get_browser
)

class TestBrowser(unittest.TestCase):
    def setUp(self) -> None:
        self.sample_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Wide Security Testing Lab</title>
            <script>console.log("ignore script");</script>
            <style>body { color: red; }</style>
        </head>
        <body>
            <h1>Application Security Dashboard</h1>
            <p>Welcome to the autonomous security agent target portal.</p>
            <form action="/login" method="POST">
                <input type="text" name="username" placeholder="Enter username" />
                <input type="password" name="password" placeholder="Enter password" />
                <button type="submit">Log In</button>
            </form>
            <div>
                <a href="/docs/api">API Documentation</a>
                <a href="/vulns/sqli">SQL Injection Vulnerability</a>
            </div>
        </body>
        </html>
        """

    def test_page_html_parser(self) -> None:
        parser = _PageHTMLParser()
        parser.feed(self.sample_html)

        self.assertEqual(parser.title, "Wide Security Testing Lab")
        self.assertTrue(len(parser.elements) >= 4)

        roles = [e.role for e in parser.elements]
        self.assertIn("input[text]", roles)
        self.assertIn("input[password]", roles)
        self.assertIn("button", roles)
        self.assertIn("link", roles)

        links = [e for e in parser.elements if e.role == "link"]
        self.assertEqual(len(links), 2)
        self.assertEqual(links[0].href, "/docs/api")
        self.assertEqual(links[1].href, "/vulns/sqli")

        self.assertNotIn("ignore script", parser.text_parts)
        self.assertNotIn("color: red", parser.text_parts)

    def test_browser_controller_operations(self) -> None:
        ctrl = BrowserController(headless=True)
        ctrl.state.url = "https://lab.wide.internal/dashboard"
        ctrl.state.raw_html = self.sample_html
        parser = _PageHTMLParser()
        parser.feed(self.sample_html)
        ctrl.state.title = parser.title
        ctrl.state.elements = parser.elements
        ctrl.state.text_content = "\n".join(parser.text_parts)

        view = ctrl.render_view()
        self.assertIn("Page Title: Wide Security Testing Lab", view)
        self.assertIn("Current URL: https://lab.wide.internal/dashboard", view)
        self.assertIn("API Documentation", view)

        fill_res = ctrl.fill("username", "admin_sec")
        self.assertIn("Filled", fill_res)
        self.assertEqual(ctrl.form_inputs.get("username"), "admin_sec")

        extract_res = ctrl.extract("Autonomous")
        self.assertIn("autonomous security agent target portal", extract_res.lower())

        shot_res = ctrl.screenshot()
        self.assertIn("BROWSER VIEWPORT SNAPSHOT", shot_res)
        self.assertIn("Wide Security Testing Lab", shot_res)

        close_res = ctrl.close()
        self.assertIn("Browser closed", close_res)
        self.assertEqual(ctrl.state.url, "about:blank")

    def test_browser_tools_execution(self) -> None:
        browser = get_browser()
        browser.state.url = "https://app.wide.local/test"
        browser.state.raw_html = self.sample_html
        parser = _PageHTMLParser()
        parser.feed(self.sample_html)
        browser.state.title = parser.title
        browser.state.elements = parser.elements
        browser.state.text_content = "\n".join(parser.text_parts)

        ctx = {"working_directory": "."}

        type_res = browser_type_tool.execute({"target": "username", "text": "agent_user"}, ctx)
        self.assertTrue(type_res.success)
        self.assertIn("Filled", type_res.output)

        extract_res = browser_extract_tool.execute({"query": "Security"}, ctx)
        self.assertTrue(extract_res.success)
        self.assertIn("Security", extract_res.output)

        shot_res = browser_screenshot_tool.execute({}, ctx)
        self.assertTrue(shot_res.success)
        self.assertIn("SNAPSHOT", shot_res.output)

        snap_res = browser_snapshot_tool.execute({}, ctx)
        self.assertTrue(snap_res.success)
        self.assertIn("@e1", snap_res.output)

        scroll_res = browser_scroll_tool.execute({"direction": "down", "pixels": 200}, ctx)
        self.assertTrue(scroll_res.success)

        console_res = browser_console_tool.execute({}, ctx)
        self.assertTrue(console_res.success)

        cookie_res = browser_cookies_tool.execute({"action": "set", "name": "sid", "value": "val"}, ctx)
        self.assertTrue(cookie_res.success)

        for name in (
            "browser_open", "browser_navigate", "browser_snapshot", "browser_click",
            "browser_type", "browser_press", "browser_hover", "browser_select",
            "browser_scroll", "browser_wait", "browser_extract", "browser_screenshot",
            "browser_console", "browser_cookies", "browser_eval", "browser_export_har",
            "browser_close"
        ):
            self.assertIn(name, DEFAULT_TOOLS)

        close_res = browser_close_tool.execute({}, ctx)
        self.assertTrue(close_res.success)
        self.assertIn("Browser closed", close_res.output)

    def test_emoji_strip_stealth_and_har_export(self) -> None:
        import http.server
        import json
        import os
        import threading

        self.assertEqual(strip_browser_emojis("\U0001F680 Wide \u2B50 Lab"), "Wide Lab")

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                body = "<html><head><title>\U0001F680 Live Lab</title></head><body>ok</body></html>".encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Set-Cookie", "sid=secret_value")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        prev_env = os.environ.get("WIDE_SDK_BROWSER_HTTP_ONLY")
        os.environ["WIDE_SDK_BROWSER_HTTP_ONLY"] = "1"
        try:
            port = server.server_address[1]
            ctrl = BrowserController(headless=True)
            out = ctrl.open(f"http://127.0.0.1:{port}/?a=1", stealth=True)
            self.assertIn("Page Title: Live Lab", out)
            self.assertTrue(ctrl.stealth)
            har = ctrl.export_har()
            self.assertEqual(har["log"]["version"], "1.2")
            self.assertEqual(len(har["log"]["entries"]), 1)
            resp_headers = har["log"]["entries"][0]["response"]["headers"]
            cookie_vals = [h["value"] for h in resp_headers if h["name"].lower() == "set-cookie"]
            self.assertEqual(cookie_vals, ["[REDACTED]"])
            har_tool_res = browser_export_har_tool.execute({}, {"working_directory": "."})
            self.assertTrue(har_tool_res.success)
            parsed_har = json.loads(har_tool_res.output)
            self.assertEqual(parsed_har["log"]["version"], "1.2")
            ctrl.close()
        finally:
            if prev_env is None:
                os.environ.pop("WIDE_SDK_BROWSER_HTTP_ONLY", None)
            else:
                os.environ["WIDE_SDK_BROWSER_HTTP_ONLY"] = prev_env
            server.shutdown()
            server.server_close()

if __name__ == "__main__":
    unittest.main()
