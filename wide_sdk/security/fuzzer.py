import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Dict, List, Optional
from .payloads import get_payloads_for_type


@dataclass
class FuzzFinding:
    payload: str
    status_code: int
    reflection_found: bool
    sql_error_detected: bool
    length_diff: int
    elapsed_ms: int
    indicator: str


@dataclass
class FuzzReport:
    url: str
    param: str
    payload_type: str
    location: str
    baseline_status: int
    baseline_length: int
    baseline_elapsed_ms: int
    findings: List[FuzzFinding]
    is_vulnerable: bool
    summary: str


SQL_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"warning: mysql", re.IGNORECASE),
    re.compile(r"unclosed quotation mark after the character string", re.IGNORECASE),
    re.compile(r"quoted string not properly terminated", re.IGNORECASE),
    re.compile(r"postgresql.*?error", re.IGNORECASE),
    re.compile(r"sqlite3::SQLException", re.IGNORECASE),
    re.compile(r"syntax error in query expression", re.IGNORECASE),
    re.compile(r"microsoft ole db provider for sql server", re.IGNORECASE),
]

TRAVERSAL_MARKERS = [re.compile(r"root:[x*]:0:0:"), re.compile(r"\[extensions\]", re.IGNORECASE), re.compile(r"\[fonts\]", re.IGNORECASE)]
CMD_MARKERS = [re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+"), re.compile(r"Windows IP Configuration", re.IGNORECASE), re.compile(r"Volume Serial Number", re.IGNORECASE)]
SSRF_MARKERS = [re.compile(r"ami-id", re.IGNORECASE), re.compile(r"instance-id", re.IGNORECASE), re.compile(r"computeMetadata", re.IGNORECASE)]


def _build_fuzz_request(
    parsed: urllib.parse.ParseResult,
    param: str,
    value: str,
    method: str,
    location: str,
    custom_headers: Optional[Dict[str, str]] = None,
) -> urllib.request.Request:
    headers: Dict[str, str] = {"User-Agent": "Wide-SDK-Agent/1.0"}
    if custom_headers:
        headers.update(custom_headers)
    upper_method = (method or "GET").upper()

    if location == "json":
        headers["Content-Type"] = "application/json"
        body = json.dumps({param: value}).encode("utf-8")
        return urllib.request.Request(urllib.parse.urlunparse(parsed), data=body, headers=headers, method=upper_method)
    if location == "form":
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = urllib.parse.urlencode({param: value}).encode("utf-8")
        return urllib.request.Request(urllib.parse.urlunparse(parsed), data=body, headers=headers, method=upper_method)
    if location == "header":
        headers[param] = value
        return urllib.request.Request(urllib.parse.urlunparse(parsed), headers=headers, method=upper_method)
    if location == "cookie":
        headers["Cookie"] = f"{param}={urllib.parse.quote(value)}"
        return urllib.request.Request(urllib.parse.urlunparse(parsed), headers=headers, method=upper_method)
    if location == "path":
        token = f"{{{param}}}"
        decoded = urllib.parse.unquote(parsed.path)
        new_path = decoded.replace(token, urllib.parse.quote(value)) if token in decoded else f"{parsed.path.rstrip('/')}/{urllib.parse.quote(value)}"
        target = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, new_path, parsed.params, parsed.query, parsed.fragment))
        return urllib.request.Request(target, headers=headers, method=upper_method)

    params = urllib.parse.parse_qs(parsed.query)
    params[param] = [value]
    query = urllib.parse.urlencode(params, doseq=True)
    target_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))
    return urllib.request.Request(target_url, headers=headers, method=upper_method)


def _detect_evidence(
    payload_type: str,
    payload: str,
    body: str,
    baseline_body: str,
    status_code: int,
    baseline_status: int,
    elapsed_ms: int,
    baseline_elapsed_ms: int,
) -> Optional[str]:
    if payload_type == "sqli":
        for pat in SQL_ERROR_PATTERNS:
            if pat.search(body) and not pat.search(baseline_body):
                return "SQL Syntax Error Triggered"
        if re.search(r"SLEEP\(", payload, re.IGNORECASE) and (elapsed_ms - baseline_elapsed_ms) >= 3500:
            return f"Time-Based SQLi Delay ({elapsed_ms}ms vs {baseline_elapsed_ms}ms baseline)"
    if payload_type == "xss" and payload in body:
        return "Raw Unencoded Reflection Detected"
    if payload_type == "ssti" and re.search(r"\b7\*7\b", payload) and "49" in body and "49" not in baseline_body:
        return "SSTI Arithmetic Evaluation Detected (7*7 -> 49)"
    if payload_type == "traversal" and any(p.search(body) and not p.search(baseline_body) for p in TRAVERSAL_MARKERS):
        return "Arbitrary Local File Marker Exposed"
    if payload_type == "cmd" and any(p.search(body) and not p.search(baseline_body) for p in CMD_MARKERS):
        return "OS Command Execution Output Detected"
    if payload_type == "ssrf" and any(p.search(body) and not p.search(baseline_body) for p in SSRF_MARKERS):
        return "Internal Metadata Response Exposed via SSRF"
    if status_code == 500 and baseline_status == 200:
        return "Server Internal Error (HTTP 500)"
    return None


def fuzz_endpoint(
    url: str,
    param: str,
    payload_type: str,
    method: str = "GET",
    location: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    compare_headers: Optional[Dict[str, str]] = None,
) -> FuzzReport:
    ptype = payload_type.lower().strip()
    loc = location or ("query" if (method or "GET").upper() in ("GET", "HEAD") else "form")
    payloads = ["1"] if ptype == "idor" else get_payloads_for_type(ptype)
    if not payloads:
        raise ValueError(f"Unsupported payload type: '{payload_type}'")

    parsed = urllib.parse.urlparse(url)
    req = _build_fuzz_request(parsed, param, "testbaselinevalue123", method, loc, headers)
    baseline_status = 200
    baseline_body = ""
    baseline_elapsed_ms = 0

    try:
        t0 = time.monotonic()
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            baseline_status = resp.status
            baseline_body = resp.read().decode("utf-8", errors="replace")
        baseline_elapsed_ms = int((time.monotonic() - t0) * 1000)
    except Exception as e:
        raise RuntimeError(f"Baseline probe failed for {url}: {str(e)}")

    findings: List[FuzzFinding] = []

    if ptype == "idor" and compare_headers:
        r_req = _build_fuzz_request(parsed, param, "testbaselinevalue123", method, loc, compare_headers)
        try:
            t0 = time.monotonic()
            with urllib.request.urlopen(r_req, timeout=10.0) as r_resp:
                r_status = r_resp.status
                r_body = r_resp.read().decode("utf-8", errors="replace")
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            if 200 <= baseline_status < 300 and 200 <= r_status < 300 and r_body == baseline_body and baseline_body:
                findings.append(FuzzFinding(
                    payload="auth-context-replay",
                    status_code=r_status,
                    reflection_found=False,
                    sql_error_detected=False,
                    length_diff=0,
                    elapsed_ms=elapsed_ms,
                    indicator="Differential Access Control Failure (secondary credentials received identical 2xx body)",
                ))
        except Exception:
            pass

    if ptype != "idor":
        for payload in payloads:
            p_req = _build_fuzz_request(parsed, param, payload, method, loc, headers)
            try:
                t0 = time.monotonic()
                with urllib.request.urlopen(p_req, timeout=10.0) as resp:
                    status_code = resp.status
                    body = resp.read().decode("utf-8", errors="replace")
                elapsed_ms = int((time.monotonic() - t0) * 1000)
            except urllib.error.HTTPError as e:
                status_code = e.code
                body = e.read().decode("utf-8", errors="replace") if e.fp else ""
                elapsed_ms = int((time.monotonic() - t0) * 1000)
            except Exception:
                continue

            indicator = _detect_evidence(ptype, payload, body, baseline_body, status_code, baseline_status, elapsed_ms, baseline_elapsed_ms)
            if indicator:
                findings.append(FuzzFinding(
                    payload=payload,
                    status_code=status_code,
                    reflection_found=payload in body,
                    sql_error_detected=(indicator == "SQL Syntax Error Triggered"),
                    length_diff=abs(len(body) - len(baseline_body)),
                    elapsed_ms=elapsed_ms,
                    indicator=indicator,
                ))

    is_vuln = len(findings) > 0
    summary = (
        f"Endpoint {url} parameter '{param}' ({loc}) appears VULNERABLE to {payload_type.upper()}. {len(findings)} anomalies confirmed."
        if is_vuln else
        f"Endpoint {url} parameter '{param}' ({loc}) tested with {len(payloads)} {payload_type.upper()} payloads. No high-confidence anomalies."
    )

    return FuzzReport(
        url=url,
        param=param,
        payload_type=payload_type,
        location=loc,
        baseline_status=baseline_status,
        baseline_length=len(baseline_body),
        baseline_elapsed_ms=baseline_elapsed_ms,
        findings=findings,
        is_vulnerable=is_vuln,
        summary=summary,
    )
