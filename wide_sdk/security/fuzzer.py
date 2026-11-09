import re
import urllib.request
import urllib.parse
from dataclasses import dataclass
from typing import List
from .payloads import get_payloads_for_type

@dataclass
class FuzzFinding:
    payload: str
    status_code: int
    reflection_found: bool
    sql_error_detected: bool
    length_diff: int
    indicator: str

@dataclass
class FuzzReport:
    url: str
    param: str
    payload_type: str
    baseline_status: int
    baseline_length: int
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
    re.compile(r"microsoft ole db provider for sql server", re.IGNORECASE)
]

def fuzz_endpoint(url: str, param: str, payload_type: str, method: str = "GET") -> FuzzReport:
    payloads = get_payloads_for_type(payload_type)
    if not payloads:
        raise ValueError(f"Unsupported payload type: '{payload_type}'")

    parsed = urllib.parse.urlparse(url)
    baseline_params = urllib.parse.parse_qs(parsed.query)
    baseline_params[param] = ["testbaselinevalue123"]
    baseline_query = urllib.parse.urlencode(baseline_params, doseq=True)

    baseline_url = urllib.parse.urlunparse((
        parsed.scheme, parsed.netloc, parsed.path, parsed.params, baseline_query, parsed.fragment
    ))

    req = urllib.request.Request(baseline_url, headers={"User-Agent": "Wide-SDK-Agent/1.0"}, method=method)
    baseline_status = 200
    baseline_body = ""

    try:
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            baseline_status = resp.status
            baseline_body = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        raise RuntimeError(f"Baseline probe failed for {url}: {str(e)}")

    findings: List[FuzzFinding] = []

    for payload in payloads:
        p_query_params = urllib.parse.parse_qs(parsed.query)
        p_query_params[param] = [payload]
        p_query = urllib.parse.urlencode(p_query_params, doseq=True)

        target_url = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path, parsed.params, p_query, parsed.fragment
        ))

        p_req = urllib.request.Request(target_url, headers={"User-Agent": "Wide-SDK-Agent/1.0"}, method=method)

        try:
            with urllib.request.urlopen(p_req, timeout=10.0) as resp:
                status_code = resp.status
                body = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            status_code = e.code
            body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        except Exception:
            continue

        length_diff = abs(len(body) - len(baseline_body))
        reflection_found = payload in body

        sql_error_detected = False
        if payload_type == "sqli":
            for pat in SQL_ERROR_PATTERNS:
                if pat.search(body) and not pat.search(baseline_body):
                    sql_error_detected = True
                    break

        indicator = "Normal"
        if sql_error_detected:
            indicator = "SQL Syntax Error Triggered"
        elif reflection_found and payload_type == "xss":
            indicator = "Raw Unencoded Reflection Detected"
        elif status_code == 500 and baseline_status == 200:
            indicator = "Server Internal Error (HTTP 500)"

        if sql_error_detected or (reflection_found and payload_type == "xss") or (status_code == 500 and baseline_status == 200):
            findings.append(FuzzFinding(
                payload=payload,
                status_code=status_code,
                reflection_found=reflection_found,
                sql_error_detected=sql_error_detected,
                length_diff=length_diff,
                indicator=indicator
            ))

    is_vuln = len(findings) > 0
    summary = (
        f"Endpoint {url} parameter '{param}' appears VULNERABLE to {payload_type.upper()}. {len(findings)} anomalies confirmed."
        if is_vuln else
        f"Endpoint {url} parameter '{param}' tested with {len(payloads)} {payload_type.upper()} payloads. No high-confidence anomalies."
    )

    return FuzzReport(
        url=url,
        param=param,
        payload_type=payload_type,
        baseline_status=baseline_status,
        baseline_length=len(baseline_body),
        findings=findings,
        is_vulnerable=is_vuln,
        summary=summary
    )
