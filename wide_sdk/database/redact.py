import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

SECRET_COLUMN_RE = re.compile(
    r"(password|passwd|pwd|pass_hash|password_hash|secret|token|refresh_token|"
    r"access_token|api_key|private_key|salt|ssn|credit_card|card_number|cvv)",
    re.IGNORECASE,
)

PII_COLUMN_RE = re.compile(
    r"(email|e_mail|phone|mobile|ssn|social_security|tax_id|passport|"
    r"birth_date|dob|address|street|ip_address|credit_card|card_number|iban)",
    re.IGNORECASE,
)

_DSN_CRED_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^:\s/@]+):([^@\s/]+)@")

_SQL_READONLY_RE = re.compile(r"^(SELECT|WITH|SHOW|DESCRIBE|DESC|EXPLAIN)\b", re.IGNORECASE)
_REDIS_READONLY_CMDS = frozenset({
    "PING", "INFO", "DBSIZE", "SCAN", "TYPE", "TTL", "PTTL", "GET", "MGET",
    "HGET", "HGETALL", "HKEYS", "HLEN", "LRANGE", "LLEN", "LINDEX",
    "SMEMBERS", "SCARD", "SISMEMBER", "ZRANGE", "ZCARD", "ZSCORE", "EXISTS", "KEYS",
})

_DESTRUCTIVE_SQL_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bDROP\s+(TABLE|DATABASE|SCHEMA|VIEW|INDEX|TRIGGER|FUNCTION|PROCEDURE|USER|ROLE)\b", re.IGNORECASE), "destructive DROP statement"),
    (re.compile(r"\bTRUNCATE\b", re.IGNORECASE), "destructive TRUNCATE statement"),
    (re.compile(r"\bALTER\s+(TABLE|DATABASE|SCHEMA|SYSTEM|USER|ROLE)\b", re.IGNORECASE), "schema/system modification (ALTER)"),
    (re.compile(r"\b(GRANT|REVOKE)\b", re.IGNORECASE), "privilege change (GRANT/REVOKE)"),
    (re.compile(r"\b(ATTACH|DETACH)\s+DATABASE\b", re.IGNORECASE), "database attach/detach operation"),
    (re.compile(r"\bPRAGMA\s+writable_schema\b", re.IGNORECASE), "dangerous SQLite PRAGMA writable_schema"),
]


def mask_dsn(text: str) -> str:
    """Mask inline password in database URIs (e.g. postgresql://user:****@host/db)."""
    return _DSN_CRED_RE.sub(r"\1:****@", str(text or ""))


def redact_row(row: Dict[str, Any], columns: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    keys = list(columns) if columns is not None else list(row.keys())
    out: Dict[str, Any] = {}
    for k in keys:
        val = row.get(k)
        if SECRET_COLUMN_RE.search(k) and val is not None:
            out[k] = "[REDACTED]"
        elif isinstance(val, (bytes, bytearray, memoryview)):
            out[k] = f"<bytes {len(val)}>"
        else:
            out[k] = val
    return out


def redact_rows(rows: Sequence[Dict[str, Any]], columns: Optional[Sequence[str]] = None) -> List[Dict[str, Any]]:
    return [redact_row(r, columns=columns) for r in rows]


def strip_sql_comments_and_literals(sql: str) -> str:
    """Strip SQL comments and replace string/quoted identifier contents safely."""
    out: List[str] = []
    i = 0
    s = str(sql or "")
    n = len(s)
    while i < n:
        ch = s[i]
        nxt = s[i + 1] if i + 1 < n else ""
        if ch == "-" and nxt == "-":
            while i < n and s[i] != "\n":
                i += 1
            out.append(" ")
            continue
        if ch == "#":
            while i < n and s[i] != "\n":
                i += 1
            out.append(" ")
            continue
        if ch == "/" and nxt == "*":
            i += 2
            while i < n and not (s[i] == "*" and (i + 1 < n and s[i + 1] == "/")):
                i += 1
            i += 2
            out.append(" ")
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            out.append("''" if quote == "'" else " ")
            i += 1
            while i < n:
                if s[i] == quote:
                    if i + 1 < n and s[i + 1] == quote:
                        i += 2
                        continue
                    i += 1
                    break
                if s[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def split_sql_statements(sql: str) -> List[str]:
    stripped = strip_sql_comments_and_literals(sql)
    return [re.sub(r"\s+", " ", part).strip() for part in stripped.split(";") if part.strip()]


def is_query_readonly(query: str, kind: str = "sqlite") -> bool:
    trimmed = str(query or "").strip()
    if not trimmed:
        return True
    if kind == "redis":
        cmd = trimmed.split(None, 1)[0].upper()
        return cmd in _REDIS_READONLY_CMDS

    stmts = split_sql_statements(trimmed)
    if not stmts:
        return True
    for stmt in stmts:
        if _SQL_READONLY_RE.match(stmt):
            if re.search(r"\bINTO\s+(OUTFILE|DUMPFILE)\b", stmt, re.IGNORECASE):
                return False
            continue
        if re.match(r"^PRAGMA\b", stmt, re.IGNORECASE):
            if "=" in stmt or re.search(r"\bwritable_schema\b", stmt, re.IGNORECASE):
                return False
            continue
        return False
    return True


def assess_sql_risk(query: str, kind: str = "sqlite") -> Tuple[bool, str]:
    raw = str(query or "").strip()
    if not raw:
        return False, ""
    if kind == "redis":
        cmd = raw.split(None, 1)[0].upper()
        if cmd in ("FLUSHALL", "FLUSHDB", "DEL", "UNLINK", "RENAME", "CONFIG", "SHUTDOWN", "DEBUG"):
            return True, f"destructive Redis command ({cmd})"
        return False, ""

    for stmt in split_sql_statements(raw):
        for pat, reason in _DESTRUCTIVE_SQL_PATTERNS:
            if pat.search(stmt):
                return True, reason
        if re.match(r"^\s*DELETE\b", stmt, re.IGNORECASE):
            has_where = bool(re.search(r"\bWHERE\b", stmt, re.IGNORECASE))
            trivial = bool(re.search(r"\bWHERE\s+(1\s*=\s*1|TRUE|NOT\s+FALSE)\s*$", stmt, re.IGNORECASE))
            if not has_where or trivial:
                return True, "unconditional DELETE without selective WHERE clause"
        if re.match(r"^\s*UPDATE\b", stmt, re.IGNORECASE):
            has_where = bool(re.search(r"\bWHERE\b", stmt, re.IGNORECASE))
            trivial = bool(re.search(r"\bWHERE\s+(1\s*=\s*1|TRUE|NOT\s+FALSE)\s*$", stmt, re.IGNORECASE))
            if not has_where or trivial:
                return True, "unconditional UPDATE without selective WHERE clause"
    return False, ""
