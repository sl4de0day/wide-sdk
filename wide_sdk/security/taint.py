import math
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple
from ..types import Finding

SOURCE_RE = re.compile(
    "|".join([
        r"\breq(?:uest)?\.(?:query|params|body|headers|cookies|args|form|values|files|data|param)\b",
        r"\blocation\.(?:search|hash|href)\b",
        r"\bdocument\.(?:referrer|URL|cookie)\b",
        r"\.searchParams\b",
        r"searchParams\.get\s*\(",
        r"\bevent\.data\b",
        r"\bprocess\.argv\b",
        r"\brequest\.(?:GET|POST|args|form|values|json|data|params|cookies|headers|files|query_params|body)\b",
        r"\brequest\.get_json\s*\(",
        r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b",
        r"\bfile_get_contents\s*\(\s*['\"]php://input",
        r"\br\.URL\.Query\s*\(",
        r"\br\.FormValue\s*\(",
        r"\br\.PostFormValue\s*\(",
        r"\bc\.(?:Query|Param|PostForm|DefaultQuery|GetHeader)\s*\(",
        r"\bmux\.Vars\s*\(",
        r"@(?:RequestParam|PathVariable|RequestHeader|RequestBody)\b",
        r"\.getParameter(?:Values)?\s*\(",
        r"\bstd::env::args\b",
        r"\bos\.environ\b",
    ])
)

SANITISER_RE = re.compile(
    r"\b(?:sanitiz|sanitis|escapeHtml|htmlEscape|escape(?:ShellArg)?|encodeURI(?:Component)?|"
    r"DOMPurify|purify|htmlspecialchars|htmlentities|escapeshellarg|shlex\.quote|Number|parseInt|"
    r"parseFloat|Boolean|basename|realpath|allowlist|whitelist|validator|bindparam|bind_param|"
    r"PreparedStatement|prepare|Integer\.parseInt|Integer\.valueOf|intval|is_numeric|commonpath|"
    r"ConstantTimeCompare|timingSafeEqual|hash_equals)\b",
    re.IGNORECASE,
)

IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")

TAINT_SINKS: List[Dict[str, object]] = [
    {
        "id": "wide/taint-sql",
        "cwe": "CWE-89",
        "category": "INJECTION",
        "severity": "CRITICAL",
        "message": "Tainted user input reaches a SQL execution sink without parameterization.",
        "re": re.compile(r"(?:(?:\.|->)(?:query|queryRaw|execute|executeQuery|executeUpdate|raw|rawQuery|find_by_sql)\s*\(|\b(?:createStatement|db\.Query|db\.Exec|cursor\.execute)\s*\()"),
    },
    {
        "id": "wide/taint-command",
        "cwe": "CWE-78",
        "category": "INJECTION",
        "severity": "CRITICAL",
        "message": "Tainted user input reaches an OS command execution sink.",
        "re": re.compile(r"\b(?:exec|execSync|spawn|spawnSync|shell_exec|passthru|popen|proc_open|os\.system|subprocess\.(?:run|Popen|call)|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|Command::new)\s*\("),
    },
    {
        "id": "wide/taint-xss",
        "cwe": "CWE-79",
        "category": "XSS",
        "severity": "HIGH",
        "message": "Tainted user input reaches an unescaped HTML or DOM rendering sink.",
        "re": re.compile(r"(?:\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\s*\(|document\.write\s*\(|dangerouslySetInnerHTML\s*[:=]|\bres\.(?:send|write)\s*\()"),
    },
    {
        "id": "wide/taint-ssrf",
        "cwe": "CWE-918",
        "category": "NETWORK",
        "severity": "HIGH",
        "message": "Tainted user input controls the target URL of an outbound network request.",
        "re": re.compile(r"\b(?:fetch|axios(?:\.(?:get|post|put|delete|request))?|got|http\.(?:get|Get|Post|NewRequest)|https\.get|requests\.(?:get|post|put|delete|request)|urllib\.request\.urlopen|curl_exec)\s*\("),
    },
    {
        "id": "wide/taint-path",
        "cwe": "CWE-22",
        "category": "FILESYSTEM",
        "severity": "HIGH",
        "message": "Tainted user input reaches a filesystem path operation without normalization or boundary checks.",
        "re": re.compile(r"\b(?:fs\.(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|unlink|unlinkSync|rm|rmSync)|file_get_contents|file_put_contents|readfile|os\.(?:Open|ReadFile|Create)|ioutil\.ReadFile|Files\.(?:readString|readAllBytes|write)|open)\s*\("),
    },
    {
        "id": "wide/taint-redirect",
        "cwe": "CWE-601",
        "category": "NETWORK",
        "severity": "MEDIUM",
        "message": "Tainted user input controls an HTTP redirect destination without origin validation.",
        "re": re.compile(r"\b(?:res\.redirect|redirect_to|sendRedirect|http\.Redirect)\s*\("),
    },
    {
        "id": "wide/taint-code-exec",
        "cwe": "CWE-94",
        "category": "INJECTION",
        "severity": "CRITICAL",
        "message": "Tainted user input reaches dynamic code or template evaluation.",
        "re": re.compile(r"\b(?:eval|Function|vm\.runInNewContext|render_template_string|jinja2\.Template|unserialize|pickle\.loads|yaml\.unsafe_load)\s*\("),
    },
]


def _is_comment_line(text: str, lang: str) -> bool:
    t = text.strip()
    if not t:
        return True
    if t.startswith("//") or t.startswith("/*") or t.startswith("* ") or t == "*" or t.startswith("<!--"):
        return True
    if lang in ("py", "rb", "yaml", "yml", "tf", "hcl") and t.startswith("#"):
        return True
    return False


def _delimiter_delta(line: str) -> int:
    delta = 0
    in_single = False
    in_double = False
    escaped = False
    for ch in line:
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double:
            if ch in ("(", "["):
                delta += 1
            elif ch in (")", "]"):
                delta -= 1
    return delta


def build_logical_spans(lines: List[str], max_span_lines: int = 8) -> List[Tuple[int, int, str]]:
    spans: List[Tuple[int, int, str]] = []
    i = 0
    while i < len(lines):
        line_text = str(lines[i] or "")
        if not line_text.strip():
            i += 1
            continue
        depth = _delimiter_delta(line_text)
        end = i
        while depth > 0 and end + 1 < len(lines) and (end - i + 1) < max_span_lines:
            end += 1
            depth += _delimiter_delta(str(lines[end] or ""))
        joined = " ".join(str(lines[k]).strip() for k in range(i, end + 1))[:3000]
        spans.append((i + 1, end + 1, joined))
        i = end + 1
    return spans


def _has_tainted_ident(expr: str, tainted: Set[str]) -> bool:
    if not expr or not tainted:
        return False
    for m in IDENT_RE.finditer(expr):
        if m.group(0) in tainted:
            return True
    return False


def _is_expr_tainted(rhs: str, tainted: Set[str]) -> bool:
    if not rhs or SANITISER_RE.search(rhs):
        return False
    if SOURCE_RE.search(rhs):
        return True
    return _has_tainted_ident(rhs, tainted)


def _track_assignments(span_text: str, tainted: Set[str]) -> None:
    destruct = re.match(r"^(?:const|let|var)\s*\{\s*([^}]+)\}\s*=\s*([^;]+)", span_text)
    if destruct:
        is_t = _is_expr_tainted(destruct.group(2), tainted)
        for part in destruct.group(1).split(","):
            name = re.sub(r"\s*=.*$", "", part.split(":")[-1]).strip()
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
                tainted.add(name) if is_t else tainted.discard(name)
        return

    decl = re.match(r"^(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*([^;]+)", span_text)
    if decl:
        var_name, rhs = decl.group(1), decl.group(2)
        tainted.add(var_name) if _is_expr_tainted(rhs, tainted) else tainted.discard(var_name)
        return

    go_assign = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:=\s*(.+)$", span_text)
    if go_assign:
        var_name, rhs = go_assign.group(1), go_assign.group(2)
        tainted.add(var_name) if _is_expr_tainted(rhs, tainted) else tainted.discard(var_name)
        return

    assign = re.match(r"^\$?([A-Za-z_][A-Za-z0-9_]*)\s*(\+?=)\s*([^=].*)$", span_text)
    if assign:
        var_name, op, rhs = assign.group(1), assign.group(2), assign.group(3)
        if _is_expr_tainted(rhs, tainted):
            tainted.add(var_name)
        elif op != "+=":
            tainted.discard(var_name)


def _is_param_sql(span_text: str) -> bool:
    if not re.search(r"(?:query|execute|prepare)\s*\(", span_text, re.IGNORECASE):
        return False
    has_placeholder = bool(re.search(r"\$\d+|\?|%s|%d|:\w+", span_text))
    has_args = bool(re.search(r",\s*[\[(]", span_text))
    has_concat = bool(re.search(r"\+\s*[A-Za-z_$]|\$\{[^}]+\}|\.format\s*\(|f[\"']", span_text))
    return has_placeholder and has_args and not has_concat


def analyze_file_taint(
    content: str,
    lang: str,
    file_path: str,
    seed_tainted: Optional[Iterable[str]] = None,
) -> List[Finding]:
    lines = (content or "").splitlines()
    spans = build_logical_spans(lines)
    tainted: Set[str] = set(seed_tainted or [])
    findings: List[Finding] = []
    emitted: Set[str] = set()

    for idx, (start_line, end_line, span_text) in enumerate(spans):
        if _is_comment_line(span_text, lang):
            continue
        _track_assignments(span_text, tainted)

        has_source = bool(SOURCE_RE.search(span_text) or _has_tainted_ident(span_text, tainted))
        if not has_source:
            continue
        if SANITISER_RE.search(span_text) and not re.search(r"\+\s*[A-Za-z_$]|\$\{", span_text):
            continue

        prev_window = "\n".join(s[2] for s in spans[max(0, idx - 6):idx]) + "\n" + span_text

        for sink in TAINT_SINKS:
            sink_re = sink["re"]
            cwe = str(sink["cwe"])
            if not sink_re.search(span_text):  # type: ignore[union-attr]
                continue
            if cwe == "CWE-89" and _is_param_sql(span_text):
                continue
            if cwe == "CWE-22" and re.search(r"(?:commonpath|path\.relative\b|startsWith\([^)]*sep\b|realpath\b|Path\.normalize\b)", prev_window):
                continue
            if cwe == "CWE-918" and re.search(r"(?:ALLOWED_HOSTS|allowedHosts|new URL\([^)]*\)\.hostname\s*===|url\.Parse\b)", prev_window) and not re.search(r"\bfetch\s*\(\s*req\.", span_text):
                continue
            if cwe == "CWE-78" and re.search(r"\b(?:execFile|spawn|spawnSync)\s*\([^,]+,\s*\[", span_text):
                continue
            if cwe == "CWE-78" and re.search(r"\bsubprocess\.run\s*\(\s*\[", span_text) and "shell=True" not in span_text and "shell = True" not in span_text:
                continue
            if cwe == "CWE-79" and re.search(r"\bres\.send\s*\(", span_text):
                if not (re.search(r"<[a-zA-Z/]|text/html", span_text) and re.search(r"\+\s*[A-Za-z_$]|\$\{", span_text)):
                    continue

            key = f"{file_path}:{start_line}:{cwe}"
            if key in emitted:
                continue
            emitted.add(key)

            findings.append(
                Finding(
                    id=str(sink["id"]),
                    cwe=cwe,
                    category=str(sink["category"]),
                    severity=sink["severity"],  # type: ignore[arg-type]
                    file=file_path,
                    line=start_line,
                    end_line=end_line,
                    snippet=span_text[:220],
                    message=str(sink["message"]),
                    remediation=f"Validate, escape, or parameterize untrusted input before passing it into {cwe} sinks.",
                    source="taint",
                )
            )

    return findings


def _extract_call_sites(text: str) -> List[Tuple[str, str]]:
    calls: List[Tuple[str, str]] = []
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", text):
        fn_name = m.group(1)
        open_idx = m.end() - 1
        depth = 0
        in_single = False
        in_double = False
        escaped = False
        close_idx = -1
        for i in range(open_idx, len(text)):
            ch = text[i]
            if escaped:
                escaped = False
                continue
            if ch == "\\":
                escaped = True
                continue
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                in_double = not in_double
            elif not in_single and not in_double:
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        close_idx = i
                        break
        if close_idx > open_idx:
            calls.append((fn_name, text[open_idx + 1:close_idx]))
    return calls


def _split_args(arg_str: str) -> List[str]:
    args: List[str] = []
    cur: List[str] = []
    depth = 0
    in_single = False
    in_double = False
    escaped = False
    for ch in arg_str:
        if escaped:
            cur.append(ch)
            escaped = False
            continue
        if ch == "\\":
            cur.append(ch)
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            cur.append(ch)
        elif ch == '"' and not in_single:
            in_double = not in_double
            cur.append(ch)
        elif not in_single and not in_double:
            if ch in ("(", "[", "{"):
                depth += 1
                cur.append(ch)
            elif ch in (")", "]", "}"):
                depth = max(0, depth - 1)
                cur.append(ch)
            elif ch == "," and depth == 0:
                args.append("".join(cur).strip())
                cur = []
            else:
                cur.append(ch)
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        args.append(tail)
    return args


def _extract_brace_functions(lines: List[str], file_path: str) -> List[Tuple[str, List[str], int, str]]:
    defs: List[Tuple[str, List[str], int, str]] = []
    fn_re = re.compile(
        r"(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)"
        r"|(?:export\s+)?const\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>"
    )
    for i, line in enumerate(lines):
        m = fn_re.search(line)
        if not m:
            continue
        name = m.group(1) or m.group(3)
        raw_params = m.group(2) if m.group(2) is not None else (m.group(4) or "")
        if not name or len(name) < 2:
            continue
        params = [
            re.sub(r"\s*=.*$", "", re.sub(r":\s*[^=]+", "", p)).strip().lstrip(".")
            for p in raw_params.split(",")
        ]
        params = [p for p in params if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", p)]
        if not params:
            continue
        depth = 0
        started = False
        end = i
        for j in range(i, min(len(lines), i + 120)):
            for ch in lines[j]:
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
            end = j
            if started and depth <= 0:
                break
        defs.append((name, params, i + 1, "\n".join(lines[i:end + 1])))
    return defs


def _extract_python_functions(lines: List[str]) -> List[Tuple[str, List[str], int, str]]:
    defs: List[Tuple[str, List[str], int, str]] = []
    py_re = re.compile(r"^(\s*)(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(?:->[^:]+)?:", re.MULTILINE)
    for i, line in enumerate(lines):
        m = py_re.match(line)
        if not m:
            continue
        indent = len(m.group(1))
        name = m.group(2)
        params = [
            p.split(":")[0].split("=")[0].strip().lstrip("*")
            for p in (m.group(3) or "").split(",")
        ]
        params = [p for p in params if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", p) and p not in ("self", "cls")]
        if not params:
            continue
        end = i
        for j in range(i + 1, min(len(lines), i + 120)):
            t = lines[j]
            if not t.strip():
                continue
            cur_indent = len(t) - len(t.lstrip())
            if cur_indent <= indent:
                break
            end = j
        defs.append((name, params, i + 1, "\n".join(lines[i:end + 1])))
    return defs


def analyze_project_flows(files: List[Dict[str, str]]) -> List[Finding]:
    summaries: Dict[str, List[Dict[str, object]]] = {}
    all_findings: List[Finding] = []
    parsed: List[Tuple[str, str, List[Tuple[int, int, str]]]] = []

    for item in files:
        file_path = item["file"]
        lang = item["lang"]
        content = item["content"]
        lines = content.splitlines()
        all_findings.extend(analyze_file_taint(content, lang, file_path))
        parsed.append((file_path, lang, build_logical_spans(lines)))

        if lang == "py":
            fns = _extract_python_functions(lines)
        elif lang in ("js", "ts", "jsx", "tsx", "mjs", "cjs", "mts", "cts"):
            fns = _extract_brace_functions(lines, file_path)
        else:
            fns = []

        for fn_name, params, start_line, body in fns:
            for p_idx, param in enumerate(params):
                if len(param) <= 1:
                    continue
                sink_hits = analyze_file_taint(body, lang, file_path, [param])
                if not sink_hits:
                    continue
                bucket = summaries.setdefault(fn_name, [])
                for sf in sink_hits:
                    bucket.append({
                        "file": file_path,
                        "param_idx": p_idx,
                        "cwe": sf.cwe,
                        "category": sf.category,
                        "severity": sf.severity,
                        "sink_line": start_line + sf.line - 1,
                    })

    emitted: Set[str] = set()
    for file_path, lang, spans in parsed:
        local_tainted: Set[str] = set()
        for start_line, end_line, span_text in spans:
            if _is_comment_line(span_text, lang):
                continue
            _track_assignments(span_text, local_tainted)
            if re.search(r"\b(?:function|def)\s+", span_text):
                continue
            for fn_name, args_raw in _extract_call_sites(span_text):
                sum_list = summaries.get(fn_name)
                if not sum_list:
                    continue
                args = _split_args(args_raw)
                for s in sum_list:
                    p_idx = int(s["param_idx"])  # type: ignore[arg-type]
                    if p_idx >= len(args):
                        continue
                    if not _is_expr_tainted(args[p_idx], local_tainted):
                        continue
                    is_cross = str(s["file"]) != file_path
                    cwe = str(s["cwe"])
                    key = f"{file_path}:{start_line}:{cwe}:{fn_name}"
                    if key in emitted:
                        continue
                    emitted.add(key)
                    rule_id = f"wide/flow-cross-{cwe.lower()}" if is_cross else f"wide/flow-local-{cwe.lower()}"
                    msg = (
                        f"Cross-file taint flow: untrusted input passed to {fn_name}() reaches {cwe} sink at {s['file']}:{s['sink_line']}."
                        if is_cross else
                        f"Inter-procedural taint flow: untrusted input passed to {fn_name}() reaches {cwe} sink at line {s['sink_line']}."
                    )
                    all_findings.append(
                        Finding(
                            id=rule_id,
                            cwe=cwe,
                            category=str(s["category"]),
                            severity=s["severity"],  # type: ignore[arg-type]
                            file=file_path,
                            line=start_line,
                            end_line=end_line,
                            snippet=span_text[:220],
                            message=msg,
                            remediation=f"Validate or sanitize arguments passed to {fn_name}() or parameterize the sink in {s['file']}:{s['sink_line']}.",
                            source="taint",
                            cross_file=is_cross,
                        )
                    )

    return all_findings


KNOWN_SECRET_PREFIX_RE = re.compile(
    r"^(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"AIza[0-9A-Za-z\-_]{30,}|sk-(?:proj-|ant-)?[A-Za-z0-9\-_]{20,}|xox[baprs]-[0-9A-Za-z-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
KNOWN_PREFIX_DUMMY_RE = re.compile(r"(?:example|dummy|placeholder|your[_-]|changeme|replace[_-]?me|xxxxxx|000000)", re.IGNORECASE)
PLACEHOLDER_RE = re.compile(
    r"(?:example|sample|dummy|placeholder|your[_-]|changeme|replace[_-]?me|test[_-]?(?:key|token|secret)|fake|redacted|localhost|000000|123456|xxxxxx|\$\{\{?|<[A-Z0-9_]+>)",
    re.IGNORECASE,
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    length = len(value)
    for c in counts.values():
        p = c / length
        entropy -= p * math.log2(p)
    return entropy


def is_likely_real_secret(line_text: str, file_path: str = "") -> bool:
    line = str(line_text or "")
    if not line.strip():
        return False
    if re.search(r"process\.env\.|os\.environ|import\.meta\.env\.|\$\{\{?\s*secrets\.", line, re.IGNORECASE):
        return False
    is_test_file = bool(re.search(r"(?:^|[/\\])(?:test|tests|__tests__|spec|specs|fixtures?|mocks?)(?:[/\\]|$)|test_.*\.py$|\.(?:test|spec)\.[jt]sx?$", file_path, re.IGNORECASE))
    m = re.search(r'["\'`]([^"\'`\r\n]{8,})["\'`]', line) or re.search(r"[:=]\s*([A-Za-z0-9_+/=-]{12,})", line)
    candidate = m.group(1).strip() if m else line.strip()

    if KNOWN_SECRET_PREFIX_RE.search(candidate) or KNOWN_SECRET_PREFIX_RE.search(line):
        return not bool(KNOWN_PREFIX_DUMMY_RE.search(candidate))
    if PLACEHOLDER_RE.search(candidate):
        return False
    if re.match(r"^(.)\1{5,}$", candidate):
        return False
    entropy = shannon_entropy(candidate)
    if len(candidate) >= 16 and entropy < 2.8:
        return False
    if is_test_file and entropy < 3.4:
        return False
    return True
