import os
import re
import stat
from pathlib import Path
from typing import List, Dict, Optional, Literal, Any, Set
from ..types import Finding, ScanResult
from .loader import RuleLoader
from .taint import analyze_project_flows, build_logical_spans, is_likely_real_secret
from .sca import collect_imported_packages, scan_workspace_dependencies

_MAX_SCAN_FILE_BYTES = 2 * 1024 * 1024

AGENT_BEHAVIOR_ONLY_RULE_IDS: Set[str] = {
    "wide/ai-no-emojis",
    "wide/ai-no-system-prompt-leak",
    "wide/ai-direct-file-edits",
    "wide/ai-native-tool-priority",
    "wide/ai-language-matching",
}

EXTENSION_MAP: Dict[str, List[str]] = {
    ".js": ["js"],
    ".jsx": ["jsx", "js"],
    ".mjs": ["mjs", "js"],
    ".cjs": ["cjs", "js"],
    ".ts": ["ts"],
    ".tsx": ["tsx", "ts"],
    ".mts": ["mts", "ts"],
    ".cts": ["cts", "ts"],
    ".vue": ["vue", "html", "js", "ts"],
    ".svelte": ["svelte", "html", "js", "ts"],
    ".html": ["html", "htm"],
    ".htm": ["htm", "html"],
    ".py": ["py"],
    ".pyi": ["pyi", "py"],
    ".php": ["php"],
    ".java": ["java"],
    ".kt": ["kt", "kotlin"],
    ".kts": ["kts", "kt", "kotlin"],
    ".scala": ["scala", "sc"],
    ".cs": ["cs"],
    ".go": ["go"],
    ".rb": ["rb"],
    ".rs": ["rs"],
    ".c": ["c"],
    ".cpp": ["cpp", "c"],
    ".h": ["h", "c"],
    ".sql": ["sql"],
    ".json": ["json"],
    ".yaml": ["yaml", "yml"],
    ".yml": ["yml", "yaml"],
    ".tf": ["tf", "hcl"],
    ".tfvars": ["tf", "hcl"],
}

SEVERITY_RANKS: Dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


def _resolve_lang_tokens(file_path: Path) -> List[str]:
    ext = file_path.suffix.lower()
    if ext in EXTENSION_MAP:
        return EXTENSION_MAP[ext]
    base = file_path.name.lower()
    if base == "dockerfile" or base.startswith("dockerfile."):
        return ["yaml", "yml"]
    return []


def _is_comment_line(line_text: str, lang_tokens: List[str]) -> bool:
    t = line_text.strip()
    if not t:
        return True
    if lang_tokens == ["json"]:
        return False
    if t.startswith("//") or t.startswith("/*") or t.startswith("* ") or t == "*" or t.startswith("<!--"):
        return True
    if any(k in lang_tokens for k in ("py", "pyi", "rb", "yaml", "yml", "tf", "hcl")) and t.startswith("#"):
        return True
    return False


class SecurityScanner:
    def __init__(self, workspace_dir: str = ".", rules_path: Optional[str] = None) -> None:
        self.workspace_dir = Path(workspace_dir).resolve()
        self.rules_path = rules_path
        self.rules = [r for r in RuleLoader.load_rules(rules_path, self.workspace_dir) if r.id not in AGENT_BEHAVIOR_ONLY_RULE_IDS]

    def _scan_single_file(
        self,
        file_path: Path,
        rules_by_lang: Dict[str, List[Any]],
        min_rank: int,
        findings: List[Finding],
        collected_sources: List[Dict[str, str]],
        imported_packages: Set[str],
    ) -> bool:
        lang_tokens = _resolve_lang_tokens(file_path)
        if not lang_tokens:
            return False

        try:
            st = file_path.stat()
        except OSError:
            return False
        if not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_SCAN_FILE_BYTES:
            return False

        try:
            raw = file_path.read_bytes()
        except Exception:
            return False
        if b"\x00" in raw[:8192]:
            return False

        content = raw.decode("utf-8", errors="ignore")
        try:
            rel_file = str(file_path.relative_to(self.workspace_dir)).replace("\\", "/")
        except ValueError:
            rel_file = str(file_path).replace("\\", "/")

        if lang_tokens[0] not in ("json", "yaml", "yml", "tf", "hcl", "sql"):
            collected_sources.append({"file": rel_file, "lang": lang_tokens[0], "content": content})
        collect_imported_packages(content, imported_packages)

        lang_key = ",".join(lang_tokens)
        applicable_rules = rules_by_lang.get(lang_key)
        if applicable_rules is None:
            is_data_only = all(t in ("json", "yaml", "yml", "tf", "hcl") for t in lang_tokens)
            applicable_rules = [
                r for r in self.rules
                if SEVERITY_RANKS.get(r.severity, 1) >= min_rank
                and (("all" in r.languages and not is_data_only) or any(t in r.languages for t in lang_tokens))
            ]
            rules_by_lang[lang_key] = applicable_rules

        lines = content.splitlines()
        file_head = "\n".join(lines[:min(len(lines), 15)])
        spans = build_logical_spans(lines)
        seen_line_rule: Set[str] = set()

        def evaluate_candidate(text: str, line_idx: int, end_line_num: int) -> None:
            line_num = line_idx + 1
            window_slice = "\n".join(lines[max(0, line_idx - 5):min(len(lines), line_idx + 6)])
            for rule in applicable_rules:
                if not rule.pattern.search(text):
                    continue
                if rule.not_match:
                    if rule.not_match.search(text):
                        continue
                    if (rule.id.startswith("wide/xxe-") or rule.id.startswith("wide/client-crypto-")) and (
                        rule.not_match.search(window_slice) or rule.not_match.search(file_head)
                    ):
                        continue
                if rule.category == "SECRETS" and not is_likely_real_secret(text, rel_file):
                    continue
                if rule.source_pattern:
                    window_start = max(0, line_idx - 15)
                    window_text = "\n".join(lines[window_start:line_idx + 1])
                    if not rule.source_pattern.search(window_text):
                        continue
                k = f"{line_num}:{rule.id}"
                if k in seen_line_rule:
                    continue
                seen_line_rule.add(k)
                findings.append(
                    Finding(
                        id=rule.id,
                        cwe=rule.cwe,
                        category=rule.category,
                        severity=rule.severity,
                        file=rel_file,
                        line=line_num,
                        end_line=end_line_num if end_line_num > line_num else None,
                        snippet=lines[line_idx].strip(),
                        message=rule.message,
                        remediation=rule.remediation,
                        source="sast",
                    )
                )

        for idx, line in enumerate(lines):
            if len(line) > 1500:
                continue
            if re.search(r"\bwide-ignore\b", line, re.IGNORECASE):
                continue
            if idx > 0 and re.search(r"\bwide-ignore-next-line\b", lines[idx - 1], re.IGNORECASE):
                continue
            if _is_comment_line(line, lang_tokens):
                continue
            evaluate_candidate(line, idx, idx + 1)

        for start_line, end_line, span_text in spans:
            if end_line <= start_line:
                continue
            start_idx = start_line - 1
            if re.search(r"\bwide-ignore\b", lines[start_idx], re.IGNORECASE):
                continue
            if start_idx > 0 and re.search(r"\bwide-ignore-next-line\b", lines[start_idx - 1], re.IGNORECASE):
                continue
            evaluate_candidate(span_text, start_idx, end_line)

        return True

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        by_slot: Dict[str, Finding] = {}
        passthrough: List[Finding] = []
        for f in findings:
            if not f.cwe or f.cwe == "N/A" or f.source == "sca":
                passthrough.append(f)
                continue
            key = f"{f.file}:{f.line}:{f.cwe}"
            prev = by_slot.get(key)
            if not prev or SEVERITY_RANKS.get(f.severity, 1) > SEVERITY_RANKS.get(prev.severity, 1):
                by_slot[key] = f
        merged = list(by_slot.values()) + passthrough
        merged.sort(key=lambda x: (x.file, x.line, x.id))
        return merged

    def scan(
        self,
        target_path: str = ".",
        min_severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "ALL"] = "ALL",
        sca: bool = True,
        advisories: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        full_target = (self.workspace_dir / target_path).resolve()
        if not full_target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target_path}")

        min_rank = 1 if min_severity == "ALL" else SEVERITY_RANKS.get(min_severity, 1)
        ignore_dirs = {"node_modules", ".git", "dist", "build", "vendor", ".next", "target", "coverage", "__pycache__", ".venv", "venv"}

        scanned_count = 0
        findings: List[Finding] = []
        rules_by_lang: Dict[str, List[Any]] = {}
        collected_sources: List[Dict[str, str]] = []
        imported_packages: Set[str] = set()

        if full_target.is_file():
            if self._scan_single_file(full_target, rules_by_lang, min_rank, findings, collected_sources, imported_packages):
                scanned_count += 1
        else:
            for root, dirs, files in os.walk(full_target):
                dirs[:] = [d for d in dirs if d not in ignore_dirs]
                for file_name in files:
                    if self._scan_single_file(Path(root) / file_name, rules_by_lang, min_rank, findings, collected_sources, imported_packages):
                        scanned_count += 1

        if collected_sources:
            for flow in analyze_project_flows(collected_sources):
                if SEVERITY_RANKS.get(flow.severity, 1) >= min_rank:
                    findings.append(flow)

        final_findings = self._deduplicate_findings(findings)

        if sca and not full_target.is_file():
            adv_db = advisories if advisories is not None else RuleLoader.load_advisories(self.workspace_dir)
            final_findings.extend(
                scan_workspace_dependencies(
                    full_target,
                    adv_db,
                    min_rank,
                    SEVERITY_RANKS,
                    imported_packages if imported_packages else None,
                )
            )

        summary = {
            "critical": len([f for f in final_findings if f.severity == "CRITICAL"]),
            "high": len([f for f in final_findings if f.severity == "HIGH"]),
            "medium": len([f for f in final_findings if f.severity == "MEDIUM"]),
            "low": len([f for f in final_findings if f.severity == "LOW"]),
        }

        return ScanResult(
            total_files_scanned=scanned_count,
            findings=final_findings,
            summary=summary,
        )

    def format_cli_report(self, result: ScanResult) -> str:
        if not result.findings:
            return f"Wide Security Scan complete: 0 vulnerabilities found in {result.total_files_scanned} files scanned."

        lines = [
            f"Wide Security Scan: Found {len(result.findings)} issue(s) across {result.total_files_scanned} scanned files.",
            f"Summary: [CRITICAL: {result.summary['critical']}] [HIGH: {result.summary['high']}] [MEDIUM: {result.summary['medium']}] [LOW: {result.summary['low']}]\n",
        ]

        for f in result.findings:
            lines.append(f"[{f.severity}] {f.category} ({f.cwe}) in {f.file}:{f.line}")
            lines.append(f"  Message:     {f.message}")
            lines.append(f"  Code:        {f.snippet}")
            lines.append(f"  Remediation: {f.remediation}\n")

        return "\n".join(lines)
