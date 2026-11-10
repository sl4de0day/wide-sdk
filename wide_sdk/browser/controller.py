import re
import urllib.request
import urllib.parse
import urllib.error
from html.parser import HTMLParser
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field

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

    def handle_starttag(self, tag: str, attrs: List[tuple[str, Optional[str]]]) -> None:
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
                value=val
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
                name=name
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

class BrowserController:
    def __init__(self, headless: bool = True, timeout: int = 15) -> None:
        self.headless = headless
        self.timeout = timeout
        self.state = BrowserState()
        self.form_inputs: Dict[str, str] = {}
        self._user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Wide/0.291126"

    def navigate(self, url: str) -> str:
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url

        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": self._user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9"
            }
        )

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

    def click(self, target: str) -> str:
        if not self.state.elements:
            return "No interactive elements on current page."

        target_clean = target.strip().lower()
        matched: Optional[DOMElement] = None

        if target_clean.startswith("[") and target_clean.endswith("]"):
            try:
                idx = int(target_clean[1:-1])
                for el in self.state.elements:
                    if el.index == idx:
                        matched = el
                        break
            except ValueError:
                pass
        else:
            try:
                idx = int(target_clean)
                for el in self.state.elements:
                    if el.index == idx:
                        matched = el
                        break
            except ValueError:
                pass

        if not matched:
            for el in self.state.elements:
                if target_clean in el.text.lower() or target_clean in (el.name or "").lower():
                    matched = el
                    break

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
        target_clean = target.strip().lower()
        matched: Optional[DOMElement] = None

        if target_clean.startswith("[") and target_clean.endswith("]"):
            try:
                idx = int(target_clean[1:-1])
                for el in self.state.elements:
                    if el.index == idx:
                        matched = el
                        break
            except ValueError:
                pass
        else:
            try:
                idx = int(target_clean)
                for el in self.state.elements:
                    if el.index == idx:
                        matched = el
                        break
            except ValueError:
                pass

        if not matched:
            for el in self.state.elements:
                if el.tag in ("input", "textarea") and (
                    target_clean in el.text.lower() or
                    target_clean in (el.name or "").lower() or
                    target_clean in el.attributes.get("placeholder", "").lower()
                ):
                    matched = el
                    break

        field_name = (matched.name if matched and matched.name else target_clean) or "input"
        self.form_inputs[field_name] = text

        if submit:
            return self.click("submit")

        matched_desc = f"[{matched.index}] {matched.role}" if matched else field_name
        return f"Filled {matched_desc} with '{text}'."

    def extract(self, query: str = "") -> str:
        if not self.state.raw_html:
            return "No page currently loaded."

        lines = []
        lines.append(f"Page Title: {self.state.title}")
        lines.append(f"Page URL: {self.state.url}")
        lines.append(f"Status Code: {self.state.status_code}")
        lines.append("")

        if query:
            q_lower = query.lower()
            matched_lines = [l for l in self.state.text_content.splitlines() if q_lower in l.lower()]
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

    def screenshot(self) -> str:
        lines = [
            f"+----------------------------------------------------------------+",
            f"| BROWSER VIEWPORT SNAPSHOT: {self.state.title[:40]:<40} |",
            f"| URL: {self.state.url[:55]:<55} |",
            f"| Status: {self.state.status_code:<54} |",
            f"+----------------------------------------------------------------+",
        ]
        sample_elements = self.state.elements[:12]
        for el in sample_elements:
            lines.append(f"| [{el.index:02d}] {el.role:<14} | {el.text[:42]:<42} |")
        lines.append(f"+----------------------------------------------------------------+")
        return "\n".join(lines)

    def render_view(self) -> str:
        out = [
            f"Page Title: {self.state.title}",
            f"Current URL: {self.state.url}",
            f"Status Code: {self.state.status_code}",
            "",
            "Interactive Elements (use index or text to click/fill):"
        ]

        if not self.state.elements:
            out.append("(No interactive elements found)")
        else:
            for el in self.state.elements[:25]:
                extra = f" -> {el.href}" if el.href else ""
                out.append(f"[{el.index}] {el.role}: {el.text}{extra}")

        out.append("")
        out.append("Page Content Preview:")
        preview = self.state.text_content[:1500] if self.state.text_content else "(Empty content)"
        out.append(preview)

        return "\n".join(out)

    def close(self) -> str:
        url = self.state.url
        self.state = BrowserState()
        self.form_inputs.clear()
        return f"Browser closed. Session ended for {url}."
