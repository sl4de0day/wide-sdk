import atexit
import base64
import hashlib
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class DOMElement:
    index: int
    tag: str
    text: str
    attributes: Dict[str, str]
    role: str
    href: Optional[str] = None
    name: Optional[str] = None
    value: Optional[str] = None
    ref: Optional[str] = None


class _PageHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.title: str = ""
        self.in_title: bool = False
        self.in_skip_tag: bool = False
        self.skip_stack: List[str] = []
        self.elements: List[DOMElement] = []
        self.text_parts: List[str] = []
        self.current_tag: Optional[str] = None
        self.current_attrs: Dict[str, str] = {}
        self.current_text: List[str] = []
        self.element_index: int = 1

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag_lower = tag.lower()
        if tag_lower == "title":
            self.in_title = True
            return

        if tag_lower in ("script", "style", "noscript", "svg"):
            self.skip_stack.append(tag_lower)
            self.in_skip_tag = True
            return

        if self.in_skip_tag:
            return

        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        self.current_tag = tag_lower
        self.current_attrs = attr_dict
        self.current_text = []

        if tag_lower == "input":
            input_type = attr_dict.get("type", "text").lower()
            name = attr_dict.get("name", "")
            val = attr_dict.get("value", "")
            placeholder = attr_dict.get("placeholder", "")
            role = f"input[{input_type}]"
            desc = placeholder or name or val or "input"
            elem = DOMElement(
                index=self.element_index,
                tag=tag_lower,
                text=desc,
                attributes=attr_dict,
                role=role,
                name=name,
                value=val,
                ref=f"@e{self.element_index}"
            )
            self.elements.append(elem)
            self.element_index += 1

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        if self.skip_stack and self.skip_stack[-1] == tag_lower:
            self.skip_stack.pop()
            self.in_skip_tag = bool(self.skip_stack)
            return

        if self.in_skip_tag:
            return

        if tag_lower == "title":
            self.in_title = False
            return

        text = " ".join("".join(self.current_text).split())

        if tag_lower in ("a", "button", "select", "textarea"):
            role = "link" if tag_lower == "a" else tag_lower
            href = self.current_attrs.get("href")
            name = self.current_attrs.get("name")
            elem = DOMElement(
                index=self.element_index,
                tag=tag_lower,
                text=text or self.current_attrs.get("aria-label", "") or self.current_attrs.get("title", "") or role,
                attributes=self.current_attrs,
                role=role,
                href=href,
                name=name,
                ref=f"@e{self.element_index}"
            )
            self.elements.append(elem)
            self.element_index += 1

        self.current_tag = None
        self.current_attrs = {}
        self.current_text = []

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title += data
            return

        if self.in_skip_tag:
            return

        cleaned = data.strip()
        if cleaned:
            self.text_parts.append(cleaned)
            if self.current_tag is not None:
                self.current_text.append(cleaned)


@dataclass
class BrowserState:
    url: str = "about:blank"
    title: str = ""
    status_code: int = 200
    elements: List[DOMElement] = field(default_factory=list)
    text_content: str = ""
    raw_html: str = ""
    history: List[str] = field(default_factory=list)
    mode: str = "http"
    last_screenshot_path: Optional[str] = None


SNAPSHOT_DOM_SCRIPT = """(() => {
  const prev = document.querySelectorAll('[data-wide-ref]');
  for (const node of prev) node.removeAttribute('data-wide-ref');
  const selector = 'a[href], button, input, select, textarea, [role="button"], [role="link"], [role="textbox"], [onclick], [tabindex]:not([tabindex="-1"])';
  const nodes = Array.from(document.querySelectorAll(selector));
  const elements = [];
  let idx = 1;
  for (const el of nodes) {
    if (!(el instanceof Element)) continue;
    const style = window.getComputedStyle(el);
    if (style.display === 'none' || style.visibility === 'hidden') continue;
    const rect = el.getBoundingClientRect();
    if (rect.width <= 0 && rect.height <= 0 && el.tagName.toLowerCase() !== 'input') continue;
    const tag = el.tagName.toLowerCase();
    const typeAttr = (el.getAttribute('type') || 'text').toLowerCase();
    if (tag === 'input' && typeAttr === 'hidden') continue;
    const ref = '@e' + idx;
    el.setAttribute('data-wide-ref', ref);
    const role = tag === 'a' ? 'link' : tag === 'input' ? ('input[' + typeAttr + ']') : (el.getAttribute('role') || tag);
    const rawText = (el.innerText || el.textContent || '').replace(/\\s+/g, ' ').trim();
    const aria = el.getAttribute('aria-label') || '';
    const placeholder = el.getAttribute('placeholder') || '';
    const name = el.getAttribute('name') || '';
    const val = ('value' in el && typeof el.value === 'string') ? el.value : (el.getAttribute('value') || '');
    const href = tag === 'a' ? (el.getAttribute('href') || '') : '';
    const text = (rawText || aria || placeholder || name || val || role).slice(0, 120);
    elements.push({
      index: idx,
      ref,
      tag,
      role,
      text,
      href,
      name,
      value: val,
      attributes: {
        id: el.id || '',
        name,
        type: typeAttr,
        placeholder,
        href,
        'aria-label': aria
      }
    });
    idx++;
    if (idx > 120) break;
  }
  const bodyText = (document.body ? (document.body.innerText || document.body.textContent || '') : '')
    .replace(/\\s+/g, ' ')
    .trim()
    .slice(0, 8000);
  return {
    url: location.href,
    title: document.title || location.href,
    textContent: bodyText,
    rawHtml: document.documentElement ? document.documentElement.outerHTML.slice(0, 50000) : '',
    elements
  };
})()"""


class _SimpleCDPClient:
    def __init__(self, timeout: int = 15) -> None:
        self.timeout = timeout
        self.proc: Optional[subprocess.Popen[bytes]] = None
        self.profile_dir: Optional[str] = None
        self.sock: Optional[socket.socket] = None
        self.next_id: int = 1
        self.console_entries: List[Dict[str, str]] = []
        self.last_status_code: int = 200
        self.load_fired: bool = False

    def connect(self, executable_path: str, headless: bool = True, proxy_url: str = "") -> None:
        self.profile_dir = tempfile.mkdtemp(prefix="wide-sdk-cdp-")
        args = [executable_path]
        if headless:
            args.append("--headless=new")
        args.extend([
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-gpu",
            "--disable-extensions",
            "--disable-background-networking",
            "--remote-debugging-port=0",
            f"--user-data-dir={self.profile_dir}"
        ])
        if proxy_url:
            args.append(f"--proxy-server={proxy_url}")
        args.append("about:blank")

        creation_flags = 0
        if os.name == "nt" and hasattr(subprocess, "CREATE_NO_WINDOW"):
            creation_flags = subprocess.CREATE_NO_WINDOW

        self.proc = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creation_flags
        )

        ws_base_url = ""
        deadline = time.time() + 15.0
        assert self.proc.stderr is not None
        stderr_acc = ""
        while time.time() < deadline:
            line_bytes = self.proc.stderr.readline()
            if not line_bytes:
                if self.proc.poll() is not None:
                    break
                time.sleep(0.05)
                continue
            stderr_acc += line_bytes.decode("utf-8", errors="replace")
            m = re.search(r"DevTools listening on (ws://[^\s]+)", stderr_acc, re.IGNORECASE)
            if m:
                ws_base_url = m.group(1)
                break

        if not ws_base_url:
            self.dispose()
            raise RuntimeError("Failed to launch Chromium/Edge DevTools endpoint")

        parsed = urllib.parse.urlparse(ws_base_url)
        http_base = f"http://{parsed.netloc}"
        page_ws_url = ""

        for _ in range(25):
            try:
                with urllib.request.urlopen(f"{http_base}/json/list", timeout=2) as resp:
                    targets = json.loads(resp.read().decode("utf-8"))
                    for t in targets:
                        if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                            page_ws_url = t["webSocketDebuggerUrl"]
                            break
                    if page_ws_url:
                        break
            except Exception:
                pass
            time.sleep(0.1)

        if not page_ws_url:
            self.dispose()
            raise RuntimeError("Could not acquire CDP page target")

        ws_parsed = urllib.parse.urlparse(page_ws_url)
        host = ws_parsed.hostname or "127.0.0.1"
        port = ws_parsed.port or 80
        ws_path = ws_parsed.path or "/"
        if ws_parsed.query:
            ws_path += f"?{ws_parsed.query}"

        sock = socket.create_connection((host, port), timeout=float(self.timeout))
        sock.settimeout(float(self.timeout))
        ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
        handshake = (
            f"GET {ws_path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode("ascii")
        sock.sendall(handshake)

        header_buf = b""
        while b"\r\n\r\n" not in header_buf:
            chunk = sock.recv(4096)
            if not chunk:
                sock.close()
                self.dispose()
                raise RuntimeError("CDP WebSocket handshake closed")
            header_buf += chunk

        header_text = header_buf.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        if " 101 " not in header_text:
            sock.close()
            self.dispose()
            raise RuntimeError(f"CDP WebSocket handshake rejected: {header_text.splitlines()[0]}")

        expected_accept = base64.b64encode(
            hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
        ).decode("ascii")
        if expected_accept not in header_text:
            sock.close()
            self.dispose()
            raise RuntimeError("CDP WebSocket Sec-WebSocket-Accept mismatch")

        self.sock = sock
        self._leftover = header_buf.split(b"\r\n\r\n", 1)[1]

        self.send("Page.enable")
        self.send("Runtime.enable")
        self.send("Network.enable")
        self.send("Emulation.setDeviceMetricsOverride", {
            "width": 1280,
            "height": 800,
            "deviceScaleFactor": 1,
            "mobile": False
        })

    def _recv_exact(self, n: int) -> bytes:
        assert self.sock is not None
        out = bytearray()
        if self._leftover:
            take = self._leftover[:n]
            out.extend(take)
            self._leftover = self._leftover[len(take):]
        while len(out) < n:
            chunk = self.sock.recv(n - len(out))
            if not chunk:
                raise ConnectionError("CDP WebSocket connection closed")
            out.extend(chunk)
        return bytes(out)

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        assert self.sock is not None
        mask_key = os.urandom(4)
        length = len(payload)
        header = bytearray([0x80 | opcode])
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))
        header.extend(mask_key)
        masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def _read_message(self) -> Optional[str]:
        chunks = bytearray()
        first_opcode: Optional[int] = None
        while True:
            b1, b2 = struct.unpack("!BB", self._recv_exact(2))
            fin = (b1 & 0x80) != 0
            opcode = b1 & 0x0F
            masked = (b2 & 0x80) != 0
            length = b2 & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._recv_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._recv_exact(8))[0]
            mask_key = self._recv_exact(4) if masked else b""
            data = self._recv_exact(length)
            if masked:
                data = bytes(b ^ mask_key[i % 4] for i, b in enumerate(data))

            if opcode == 0x8:
                return None
            if opcode == 0x9:
                self._send_frame(0xA, data)
                continue
            if opcode == 0xA:
                continue

            if first_opcode is None:
                first_opcode = opcode
            chunks.extend(data)
            if fin:
                return chunks.decode("utf-8", errors="replace")

    def _process_event(self, msg: Dict[str, Any]) -> None:
        method = msg.get("method", "")
        params = msg.get("params", {}) or {}
        if method == "Page.loadEventFired":
            self.load_fired = True
        elif method == "Network.responseReceived":
            if params.get("type") == "Document":
                status = (params.get("response") or {}).get("status")
                if isinstance(status, int):
                    self.last_status_code = status
        elif method == "Runtime.consoleAPICalled":
            args = params.get("args") or []
            text_parts = [str(a.get("value", a.get("description", ""))) for a in args if a]
            self.console_entries.append({
                "level": str(params.get("type", "log")),
                "text": " ".join(p for p in text_parts if p),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            })
            if len(self.console_entries) > 200:
                self.console_entries.pop(0)
        elif method == "Runtime.exceptionThrown":
            details = params.get("exceptionDetails") or {}
            exc = details.get("exception") or {}
            text = exc.get("description") or details.get("text") or "Runtime exception"
            self.console_entries.append({
                "level": "error",
                "text": str(text),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            })
            if len(self.console_entries) > 200:
                self.console_entries.pop(0)

    def send(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self.sock:
            raise RuntimeError("CDP session is not open")
        msg_id = self.next_id
        self.next_id += 1
        payload = json.dumps({"id": msg_id, "method": method, "params": params or {}}).encode("utf-8")
        self._send_frame(0x1, payload)

        deadline = time.time() + float(self.timeout)
        while time.time() < deadline:
            raw = self._read_message()
            if raw is None:
                raise ConnectionError("CDP socket closed")
            msg = json.loads(raw)
            if msg.get("id") == msg_id:
                if "error" in msg and msg["error"]:
                    err = msg["error"]
                    raise RuntimeError(err.get("message") if isinstance(err, dict) else str(err))
                return msg.get("result") or {}
            if "method" in msg:
                self._process_event(msg)

        raise TimeoutError(f"CDP command timed out: {method}")

    def eval_value(self, expression: str) -> Any:
        res = self.send("Runtime.evaluate", {
            "expression": expression,
            "returnByValue": True,
            "awaitPromise": True
        })
        if res.get("exceptionDetails"):
            details = res["exceptionDetails"]
            exc = details.get("exception") or {}
            raise RuntimeError(str(exc.get("description") or details.get("text") or "Evaluation error"))
        return (res.get("result") or {}).get("value")

    def dispose(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        if self.proc:
            try:
                self.proc.kill()
            except Exception:
                pass
            try:
                self.proc.wait(timeout=2)
            except Exception:
                pass
            self.proc = None
        if self.profile_dir:
            try:
                shutil.rmtree(self.profile_dir, ignore_errors=True)
            except Exception:
                pass
            self.profile_dir = None


_ACTIVE_CONTROLLERS: List["BrowserController"] = []


def _cleanup_all_controllers() -> None:
    for ctrl in list(_ACTIVE_CONTROLLERS):
        try:
            ctrl._cleanup_live_drivers()
        except Exception:
            pass


atexit.register(_cleanup_all_controllers)


class BrowserController:
    def __init__(self, headless: bool = True, timeout: int = 15) -> None:
        self.headless = headless
        self.timeout = timeout
        self.state = BrowserState()
        self.form_inputs: Dict[str, str] = {}
        self.console_buffer: List[Dict[str, str]] = []
        self.cookie_jar: Dict[str, str] = {}
        self._cdp: Optional[_SimpleCDPClient] = None
        self._pw: Any = None
        self._pw_browser: Any = None
        self._pw_context: Any = None
        self._pw_page: Any = None
        self._user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Wide/0.4141126"

    def find_system_browser_executable(self) -> Optional[str]:
        candidates: List[str] = []
        if os.name == "nt":
            local_app_data = os.environ.get("LOCALAPPDATA", "")
            program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
            program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
            candidates.extend([
                os.path.join(program_files, "Google", "Chrome", "Application", "chrome.exe"),
                os.path.join(program_files_x86, "Google", "Chrome", "Application", "chrome.exe"),
                os.path.join(local_app_data, "Google", "Chrome", "Application", "chrome.exe"),
                os.path.join(program_files_x86, "Microsoft", "Edge", "Application", "msedge.exe"),
                os.path.join(program_files, "Microsoft", "Edge", "Application", "msedge.exe"),
                os.path.join(local_app_data, "Microsoft", "Edge", "Application", "msedge.exe"),
                os.path.join(program_files, "BraveSoftware", "Brave-Browser", "Application", "brave.exe")
            ])
        elif os.uname().sysname == "Darwin":
            candidates.extend([
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
                "/Applications/Chromium.app/Contents/MacOS/Chromium"
            ])
        else:
            candidates.extend([
                "/usr/bin/google-chrome",
                "/usr/bin/google-chrome-stable",
                "/usr/bin/chromium",
                "/usr/bin/chromium-browser",
                "/usr/bin/microsoft-edge",
                "/usr/bin/brave-browser"
            ])
        for p in candidates:
            if p and os.path.exists(p):
                return p
        return None

    def _normalize_url(self, url: str) -> str:
        trimmed = url.strip()
        if not trimmed or trimmed == "about:blank":
            return "about:blank"
        if re.match(r"^(?:https?|about|data|file)://", trimmed, re.IGNORECASE):
            return trimmed
        scheme = "http://" if re.match(r"^(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(?:[:/]|$)", trimmed, re.IGNORECASE) else "https://"
        return scheme + trimmed

    def _push_console(self, level: str, text: str) -> None:
        self.console_buffer.append({
            "level": level or "log",
            "text": text or "",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        })
        if len(self.console_buffer) > 200:
            self.console_buffer.pop(0)

    def _ensure_live_session(self) -> str:
        if self._pw_page is not None:
            return "playwright"
        if self._cdp is not None:
            return "cdp"
        if os.environ.get("WIDE_SDK_BROWSER_HTTP_ONLY") == "1":
            self.state.mode = "http"
            return "http"

        if self not in _ACTIVE_CONTROLLERS:
            _ACTIVE_CONTROLLERS.append(self)

        exe = self.find_system_browser_executable()
        proxy_url = os.environ.get("WIDE_CATCHER_PROXY") or os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or ""

        try:
            from playwright.sync_api import sync_playwright
            self._pw = sync_playwright().start()
            launch_kwargs: Dict[str, Any] = {
                "headless": self.headless,
                "args": ["--no-sandbox", "--disable-gpu"]
            }
            if exe:
                launch_kwargs["executable_path"] = exe
            if proxy_url:
                launch_kwargs["proxy"] = {"server": proxy_url}
            self._pw_browser = self._pw.chromium.launch(**launch_kwargs)
            self._pw_context = self._pw_browser.new_context(viewport={"width": 1280, "height": 800})
            self._pw_page = self._pw_context.new_page()
            self._pw_page.on("console", lambda msg: self._push_console(msg.type, msg.text))
            self._pw_page.on("pageerror", lambda err: self._push_console("error", str(err)))
            self.state.mode = "playwright"
            return "playwright"
        except Exception:
            self._cleanup_live_drivers()

        if exe:
            try:
                client = _SimpleCDPClient(timeout=self.timeout)
                client.connect(exe, headless=self.headless, proxy_url=proxy_url)
                self._cdp = client
                self.state.mode = "cdp"
                return "cdp"
            except Exception:
                self._cleanup_live_drivers()

        self.state.mode = "http"
        return "http"

    def _cleanup_live_drivers(self) -> None:
        if self._pw_browser is not None:
            try:
                self._pw_browser.close()
            except Exception:
                pass
        if self._pw is not None:
            try:
                self._pw.stop()
            except Exception:
                pass
        self._pw_page = None
        self._pw_context = None
        self._pw_browser = None
        self._pw = None
        if self._cdp is not None:
            self._cdp.dispose()
            self._cdp = None
        if self in _ACTIVE_CONTROLLERS:
            _ACTIVE_CONTROLLERS.remove(self)

    def _sync_live_dom_state(self) -> None:
        snap: Optional[Dict[str, Any]] = None
        if self._pw_page is not None:
            snap = self._pw_page.evaluate(SNAPSHOT_DOM_SCRIPT)
        elif self._cdp is not None:
            snap = self._cdp.eval_value(SNAPSHOT_DOM_SCRIPT)
            self.state.status_code = self._cdp.last_status_code
        if not isinstance(snap, dict):
            return

        self.state.url = str(snap.get("url") or self.state.url)
        self.state.title = str(snap.get("title") or self.state.url)
        self.state.text_content = str(snap.get("textContent") or "")
        self.state.raw_html = str(snap.get("rawHtml") or "")
        raw_elements = snap.get("elements") or []
        parsed_elems: List[DOMElement] = []
        for item in raw_elements:
            if not isinstance(item, dict):
                continue
            parsed_elems.append(DOMElement(
                index=int(item.get("index", len(parsed_elems) + 1)),
                tag=str(item.get("tag", "div")),
                text=str(item.get("text", "")),
                attributes=dict(item.get("attributes") or {}),
                role=str(item.get("role", "element")),
                href=item.get("href") or None,
                name=item.get("name") or None,
                value=item.get("value") or None,
                ref=item.get("ref") or None
            ))
        self.state.elements = parsed_elems

    def _resolve_target(self, target: str) -> Tuple[Optional[str], Optional[DOMElement], Optional[str]]:
        clean = str(target or "").strip()
        lower = clean.lower()

        if re.match(r"^@?e\d+$", lower):
            norm_ref = lower if lower.startswith("@") else f"@{lower}"
            for el in self.state.elements:
                el_ref = (el.ref or f"@e{el.index}").lower()
                if el_ref == norm_ref:
                    return norm_ref, el, f'[data-wide-ref="{norm_ref}"]'
            return norm_ref, None, f'[data-wide-ref="{norm_ref}"]'

        if re.match(r"^(?:\[\d+\]|\d+)$", clean):
            idx = int(clean.strip("[]"))
            for el in self.state.elements:
                if el.index == idx:
                    ref = el.ref or f"@e{idx}"
                    return ref, el, f'[data-wide-ref="{ref}"]'
            ref = f"@e{idx}"
            return ref, None, f'[data-wide-ref="{ref}"]'

        for el in self.state.elements:
            if (
                lower in el.text.lower()
                or lower in (el.name or "").lower()
                or lower in el.attributes.get("placeholder", "").lower()
                or el.attributes.get("id", "").lower() == lower
            ):
                ref = el.ref or f"@e{el.index}"
                return ref, el, f'[data-wide-ref="{ref}"]'

        if clean.startswith(("#", ".", "[")) or re.match(r"^[a-z]+\[", lower):
            return None, None, clean

        return None, None, None

    def open(self, url: Optional[str] = None) -> str:
        mode = self._ensure_live_session()
        if url and url.strip():
            return self.navigate(url)
        return f"Browser session initialized (engine: {mode}, url: {self.state.url})."

    def navigate(self, url: str) -> str:
        url = self._normalize_url(url)
        mode = self._ensure_live_session()

        if mode == "playwright" and self._pw_page is not None:
            try:
                resp = self._pw_page.goto(url, wait_until="domcontentloaded", timeout=self.timeout * 1000)
                if resp is not None:
                    self.state.status_code = resp.status
                self._pw_page.wait_for_timeout(150)
                self.state.history.append(url)
                self.form_inputs.clear()
                self._sync_live_dom_state()
                return self.render_view()
            except Exception as e:
                return f"Navigation failed: {str(e)}"

        if mode == "cdp" and self._cdp is not None:
            try:
                self._cdp.load_fired = False
                self._cdp.send("Page.navigate", {"url": url})
                deadline = time.time() + float(self.timeout)
                while not self._cdp.load_fired and time.time() < deadline:
                    ready = self._cdp.eval_value("document.readyState")
                    if ready in ("complete", "interactive"):
                        break
                    time.sleep(0.1)
                time.sleep(0.15)
                self.state.history.append(url)
                self.form_inputs.clear()
                self._sync_live_dom_state()
                return self.render_view()
            except Exception as e:
                return f"Navigation failed: {str(e)}"

        headers = {
            "User-Agent": self._user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9"
        }
        if self.cookie_jar:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookie_jar.items())

        req = urllib.request.Request(url, headers=headers)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                self.state.status_code = resp.status
                self.state.url = resp.geturl()
                content_bytes = resp.read()
                raw_html = content_bytes.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            self.state.status_code = e.code
            self.state.url = url
            raw_html = e.read().decode("utf-8", errors="replace") if e.fp else ""
        except Exception as e:
            return f"Navigation failed: {str(e)}"

        self.state.raw_html = raw_html
        self.state.history.append(self.state.url)
        self.form_inputs.clear()

        parser = _PageHTMLParser()
        try:
            parser.feed(raw_html)
        except Exception:
            pass

        self.state.title = parser.title.strip() or self.state.url
        self.state.elements = parser.elements
        self.state.text_content = "\n".join(parser.text_parts[:100])

        return self.render_view()

    def snapshot(self) -> str:
        if self._pw_page is not None or self._cdp is not None:
            self._sync_live_dom_state()
        return self.render_view()

    def click(self, target: str) -> str:
        if self._pw_page is not None:
            ref, _, selector = self._resolve_target(target)
            if selector:
                self._pw_page.locator(selector).first.click(timeout=8000)
            else:
                self._pw_page.get_by_text(target, exact=False).first.click(timeout=8000)
            self._pw_page.wait_for_timeout(250)
            self._sync_live_dom_state()
            return f"Clicked {ref or target}.\n\n" + self.render_view()

        if self._cdp is not None:
            ref, _, selector = self._resolve_target(target)
            coords = self._cdp.eval_value(f"""(() => {{
                let el = {f'document.querySelector({json.dumps(selector)})' if selector else 'null'};
                if (!el) {{
                    const needle = {json.dumps(target.strip().lower())};
                    const list = Array.from(document.querySelectorAll('a,button,input,select,textarea,[role="button"],[role="link"]'));
                    el = list.find((n) => (n.innerText || n.textContent || n.getAttribute('aria-label') || '').toLowerCase().includes(needle)) || null;
                }}
                if (!el) return null;
                el.scrollIntoView({{ block: 'center', inline: 'center' }});
                const r = el.getBoundingClientRect();
                return {{ x: r.left + r.width / 2, y: r.top + r.height / 2 }};
            }})()""")
            if not coords:
                available = ", ".join(f"[{e.index}] {e.role}: {e.text[:20]}" for e in self.state.elements[:10])
                return f"Element '{target}' not found. Available elements: {available}"
            cx = max(1, int(round(coords["x"])))
            cy = max(1, int(round(coords["y"])))
            self._cdp.send("Input.dispatchMouseEvent", {"type": "mousePressed", "x": cx, "y": cy, "button": "left", "clickCount": 1})
            self._cdp.send("Input.dispatchMouseEvent", {"type": "mouseReleased", "x": cx, "y": cy, "button": "left", "clickCount": 1})
            time.sleep(0.3)
            self._sync_live_dom_state()
            return f"Clicked {ref or target}.\n\n" + self.render_view()

        if not self.state.elements:
            return "No interactive elements on current page."

        _, matched, _ = self._resolve_target(target)

        if not matched:
            available = ", ".join(f"[{e.index}] {e.role}: {e.text[:20]}" for e in self.state.elements[:10])
            return f"Element '{target}' not found. Available elements: {available}"

        if matched.href:
            target_url = urllib.parse.urljoin(self.state.url, matched.href)
            return self.navigate(target_url)

        if matched.tag == "button" or (matched.tag == "input" and matched.attributes.get("type") in ("submit", "button")):
            if self.form_inputs:
                data = urllib.parse.urlencode(self.form_inputs).encode("utf-8")
                req = urllib.request.Request(
                    self.state.url,
                    data=data,
                    headers={"User-Agent": self._user_agent, "Content-Type": "application/x-www-form-urlencoded"},
                    method="POST"
                )
                try:
                    with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                        self.state.status_code = resp.status
                        self.state.url = resp.geturl()
                        raw_html = resp.read().decode("utf-8", errors="replace")
                        self.state.raw_html = raw_html
                        parser = _PageHTMLParser()
                        parser.feed(raw_html)
                        self.state.title = parser.title.strip() or self.state.url
                        self.state.elements = parser.elements
                        self.state.text_content = "\n".join(parser.text_parts[:100])
                        return f"Form submitted successfully with {self.form_inputs}.\n\n" + self.render_view()
                except Exception as e:
                    return f"Form submission failed: {str(e)}"
            return f"Clicked [{matched.index}] {matched.role}: {matched.text}"

        return f"Clicked [{matched.index}] {matched.role}: {matched.text}"

    def fill(self, target: str, text: str, submit: bool = False) -> str:
        if self._pw_page is not None:
            ref, _, selector = self._resolve_target(target)
            if not selector:
                return f"Input element '{target}' not found."
            loc = self._pw_page.locator(selector).first
            loc.fill(text, timeout=8000)
            if submit:
                loc.press("Enter")
                self._pw_page.wait_for_timeout(250)
            self._sync_live_dom_state()
            return f"Filled {ref or target} with '{text}'."

        if self._cdp is not None:
            ref, _, selector = self._resolve_target(target)
            focused = self._cdp.eval_value(f"""(() => {{
                let el = {f'document.querySelector({json.dumps(selector)})' if selector else 'null'};
                if (!el) {{
                    const needle = {json.dumps(target.strip().lower())};
                    const list = Array.from(document.querySelectorAll('input,textarea'));
                    el = list.find((n) => ((n.name || '') + ' ' + (n.placeholder || '') + ' ' + (n.getAttribute('aria-label') || '')).toLowerCase().includes(needle)) || null;
                }}
                if (!el) return false;
                el.focus();
                el.value = {json.dumps(text)};
                el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                return true;
            }})()""")
            if not focused:
                return f"Input element '{target}' not found."
            if submit:
                self.press("Enter")
            self._sync_live_dom_state()
            return f"Filled {ref or target} with '{text}'."

        target_clean = target.strip().lower()
        _, matched, _ = self._resolve_target(target)

        if not matched:
            for el in self.state.elements:
                if el.tag in ("input", "textarea") and (
                    target_clean in el.text.lower()
                    or target_clean in (el.name or "").lower()
                    or target_clean in el.attributes.get("placeholder", "").lower()
                ):
                    matched = el
                    break

        field_name = (matched.name if matched and matched.name else target_clean) or "input"
        self.form_inputs[field_name] = text

        if submit:
            return self.click("submit")

        matched_desc = f"[{matched.index}] {matched.role}" if matched else field_name
        return f"Filled {matched_desc} with '{text}'."

    def press(self, key: str) -> str:
        if self._pw_page is not None:
            self._pw_page.keyboard.press(key)
            self._pw_page.wait_for_timeout(200)
            self._sync_live_dom_state()
            return f"Pressed key '{key}'."
        if self._cdp is not None:
            code_map = {"Enter": 13, "Tab": 9, "Escape": 27}
            vcode = code_map.get(key, 0)
            self._cdp.send("Input.dispatchKeyEvent", {"type": "keyDown", "key": key, "windowsVirtualKeyCode": vcode})
            self._cdp.send("Input.dispatchKeyEvent", {"type": "keyUp", "key": key, "windowsVirtualKeyCode": vcode})
            time.sleep(0.2)
            self._sync_live_dom_state()
            return f"Pressed key '{key}'."
        if key.lower() == "enter" and self.form_inputs:
            return self.click("submit")
        return f"Simulated key press '{key}' on {self.state.url}."

    def hover(self, target: str) -> str:
        if self._pw_page is not None:
            ref, _, selector = self._resolve_target(target)
            if selector:
                self._pw_page.locator(selector).first.hover(timeout=6000)
                return f"Hovered over {ref or target}."
        if self._cdp is not None:
            ref, _, selector = self._resolve_target(target)
            sel = selector or target
            coords = self._cdp.eval_value(f"""(() => {{
                const el = document.querySelector({json.dumps(sel)});
                if (!el) return null;
                el.scrollIntoView({{ block: 'center' }});
                const r = el.getBoundingClientRect();
                return {{ x: r.left + r.width / 2, y: r.top + r.height / 2 }};
            }})()""")
            if coords:
                self._cdp.send("Input.dispatchMouseEvent", {
                    "type": "mouseMoved",
                    "x": int(round(coords["x"])),
                    "y": int(round(coords["y"]))
                })
                return f"Hovered over {ref or target}."
        return f"Hovered over '{target}' on {self.state.url}."

    def select(self, target: str, value: str) -> str:
        if self._pw_page is not None:
            ref, _, selector = self._resolve_target(target)
            if selector:
                self._pw_page.locator(selector).first.select_option(value)
                self._sync_live_dom_state()
                return f"Selected '{value}' on {ref or target}."
        if self._cdp is not None:
            ref, _, selector = self._resolve_target(target)
            sel = selector or target
            ok = self._cdp.eval_value(f"""(() => {{
                const el = document.querySelector({json.dumps(sel)});
                if (!el || el.tagName.toLowerCase() !== 'select') return false;
                el.value = {json.dumps(value)};
                el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                return true;
            }})()""")
            if not ok:
                return f"Select element '{target}' not found."
            self._sync_live_dom_state()
            return f"Selected '{value}' on {ref or target}."
        self.form_inputs[target] = value
        return f"Selected '{value}' for '{target}'."

    def scroll(self, direction: str = "down", pixels: int = 500) -> str:
        if direction == "top":
            js = "window.scrollTo(0, 0)"
        elif direction == "bottom":
            js = "window.scrollTo(0, document.body.scrollHeight)"
        else:
            delta = -abs(int(pixels)) if direction == "up" else abs(int(pixels))
            js = f"window.scrollBy(0, {delta})"

        if self._pw_page is not None:
            self._pw_page.evaluate(js)
        elif self._cdp is not None:
            self._cdp.eval_value(js)
        return f"Scrolled {direction} ({pixels}px)."

    def wait(self, ms: int = 1000, selector: str = "", text: str = "") -> str:
        timeout_ms = min(max(int(ms), 50), 15000)
        if selector:
            if self._pw_page is not None:
                self._pw_page.wait_for_selector(selector, timeout=timeout_ms)
                self._sync_live_dom_state()
                return f"Selector '{selector}' appeared."
            if self._cdp is not None:
                deadline = time.time() + (timeout_ms / 1000.0)
                while time.time() < deadline:
                    if self._cdp.eval_value(f"Boolean(document.querySelector({json.dumps(selector)}))"):
                        self._sync_live_dom_state()
                        return f"Selector '{selector}' appeared."
                    time.sleep(0.15)
                raise TimeoutError(f"Timed out waiting for selector '{selector}'")
        if text:
            if self._pw_page is not None:
                self._pw_page.get_by_text(text).first.wait_for(timeout=timeout_ms)
                self._sync_live_dom_state()
                return f"Text '{text}' appeared."
            if self._cdp is not None:
                deadline = time.time() + (timeout_ms / 1000.0)
                while time.time() < deadline:
                    if self._cdp.eval_value(f"document.body ? document.body.innerText.includes({json.dumps(text)}) : false"):
                        self._sync_live_dom_state()
                        return f"Text '{text}' appeared."
                    time.sleep(0.15)
                raise TimeoutError(f"Timed out waiting for text '{text}'")
        time.sleep(timeout_ms / 1000.0)
        return f"Waited {timeout_ms}ms."

    def extract(self, query: str = "") -> str:
        if not self.state.raw_html and not self.state.text_content:
            return "No page currently loaded."

        lines = [
            f"Page Title: {self.state.title}",
            f"Page URL: {self.state.url}",
            f"Status Code: {self.state.status_code}",
            ""
        ]

        if query:
            q_lower = query.lower()
            matched_lines = [line for line in self.state.text_content.splitlines() if q_lower in line.lower()]
            if matched_lines:
                lines.append(f"Extracted content matching '{query}':")
                lines.extend(matched_lines[:30])
            else:
                lines.append(f"No content matched query '{query}'. Summary:")
                lines.append(self.state.text_content[:2000])
        else:
            lines.append("Extracted Text Content:")
            lines.append(self.state.text_content[:3000])

        return "\n".join(lines)

    def capture_screenshot_file(self, output_dir: Optional[str] = None) -> Optional[str]:
        png_bytes: Optional[bytes] = None
        if self._pw_page is not None:
            png_bytes = self._pw_page.screenshot(type="png")
        elif self._cdp is not None:
            res = self._cdp.send("Page.captureScreenshot", {"format": "png"})
            if res.get("data"):
                png_bytes = base64.b64decode(res["data"])
        if not png_bytes:
            return None

        base_dir = os.path.join(output_dir, ".wide", "screenshots") if output_dir else tempfile.gettempdir()
        os.makedirs(base_dir, exist_ok=True)
        out_path = os.path.join(base_dir, f"wide-sdk-browser-{int(time.time() * 1000)}.png")
        with open(out_path, "wb") as f:
            f.write(png_bytes)
        self.state.last_screenshot_path = out_path
        return out_path

    def screenshot(self, output_dir: Optional[str] = None) -> str:
        if output_dir and (self._pw_page is not None or self._cdp is not None):
            try:
                self.capture_screenshot_file(output_dir)
            except Exception:
                pass

        lines = [
            "+----------------------------------------------------------------+",
            f"| BROWSER VIEWPORT SNAPSHOT: {self.state.title[:40]:<40} |",
            f"| URL: {self.state.url[:55]:<55} |",
            f"| Status: {self.state.status_code:<54} |",
            "+----------------------------------------------------------------+",
        ]
        sample_elements = self.state.elements[:12]
        for el in sample_elements:
            lines.append(f"| [{el.index:02d}] {el.role:<14} | {el.text[:42]:<42} |")
        lines.append("+----------------------------------------------------------------+")
        if self.state.last_screenshot_path:
            lines.append(f"Screenshot saved: {self.state.last_screenshot_path}")
        return "\n".join(lines)

    def console(self, clear: bool = False) -> str:
        entries = list(self.console_buffer)
        if self._cdp is not None:
            entries.extend(self._cdp.console_entries)
        if clear:
            self.console_buffer.clear()
            if self._cdp is not None:
                self._cdp.console_entries.clear()
        return json.dumps(entries, indent=2) if entries else "No console messages."

    def cookies(self, action: str = "get", name: str = "", value: str = "", url: str = "") -> str:
        if action == "clear":
            self.cookie_jar.clear()
            if self._pw_context is not None:
                self._pw_context.clear_cookies()
            elif self._cdp is not None:
                self._cdp.send("Network.clearBrowserCookies")
            return "Cleared browser cookies."

        if action == "set" and name:
            target_url = url or (self.state.url if self.state.url.startswith("http") else "http://127.0.0.1/")
            self.cookie_jar[name] = value
            if self._pw_context is not None:
                self._pw_context.add_cookies([{"name": name, "value": value, "url": target_url}])
            elif self._cdp is not None:
                self._cdp.send("Network.setCookie", {"name": name, "value": value, "url": target_url})
            return f"Set cookie '{name}'."

        if self._pw_context is not None:
            return json.dumps(self._pw_context.cookies(), indent=2)
        if self._cdp is not None:
            res = self._cdp.send("Network.getCookies")
            return json.dumps(res.get("cookies") or [], indent=2)
        return json.dumps([{"name": k, "value": v} for k, v in self.cookie_jar.items()], indent=2)

    def eval_js(self, script: str) -> str:
        if self._pw_page is not None:
            val = self._pw_page.evaluate(script)
            return val if isinstance(val, str) else json.dumps(val, indent=2)
        if self._cdp is not None:
            val = self._cdp.eval_value(script)
            return val if isinstance(val, str) else json.dumps(val, indent=2)
        raise RuntimeError("JavaScript evaluation requires an active Chromium/Edge browser session (call browser_open or browser_navigate first).")

    def render_view(self) -> str:
        out = [
            f"Page Title: {self.state.title}",
            f"Current URL: {self.state.url}",
            f"Status Code: {self.state.status_code}",
            f"Engine: {self.state.mode}",
            "",
            "Interactive Elements (use @eN ref, index, or text to click/fill):"
        ]

        if not self.state.elements:
            out.append("(No interactive elements found)")
        else:
            for el in self.state.elements[:35]:
                ref = el.ref or f"@e{el.index}"
                extra = f" -> {el.href}" if el.href else ""
                out.append(f"[{el.index}] ({ref}) {el.role}: {el.text}{extra}")

        out.append("")
        out.append("Page Content Preview:")
        preview = self.state.text_content[:1500] if self.state.text_content else "(Empty content)"
        out.append(preview)

        return "\n".join(out)

    def close(self) -> str:
        url = self.state.url
        self._cleanup_live_drivers()
        self.console_buffer.clear()
        self.cookie_jar.clear()
        self.state = BrowserState()
        self.form_inputs.clear()
        return f"Browser closed. Session ended for {url}."
