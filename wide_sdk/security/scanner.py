import os
import stat
from pathlib import Path
from typing import List, Dict, Optional, Literal, Any
from ..types import Finding, ScanResult
from .rules import SECURITY_RULES
from .loader import RuleLoader

_MAX_SCAN_FILE_BYTES = 2 * 1024 * 1024

EXTENSION_MAP: Dict[str, str] = {
    ".js": "js",
    ".jsx": "js",
    ".mjs": "js",
    ".cjs": "js",
    ".ts": "ts",
    ".tsx": "ts",
    ".py": "py",
    ".php": "php",
    ".java": "java",
    ".cs": "cs",
    ".go": "go",
    ".rb": "rb",
    ".rs": "rs",
    ".c": "c",
    ".cpp": "c",
    ".h": "c"
}

SEVERITY_RANKS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1
}

class SecurityScanner:
    def __init__(self, workspace_dir: str = ".", rules_path: Optional[str] = None) -> None:
        self.workspace_dir = Path(workspace_dir).resolve()
        self.rules_path = rules_path
        self.rules = RuleLoader.load_rules(rules_path, self.workspace_dir)

    def _scan_single_file(
        self,
        file_path: Path,
        rules_by_lang: Dict[str, List[Any]],
        min_rank: int,
        findings: List[Finding]
    ) -> bool:
        ext = file_path.suffix.lower()
        lang = EXTENSION_MAP.get(ext)
        if not lang:
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

        applicable_rules = rules_by_lang.get(lang)
        if applicable_rules is None:
            applicable_rules = [
                r for r in self.rules
                if SEVERITY_RANKS.get(r.severity, 1) >= min_rank
                and ("all" in r.languages or lang in r.languages)
            ]
            rules_by_lang[lang] = applicable_rules

        content = raw.decode("utf-8", errors="ignore")
        lines = content.splitlines()
        try:
            rel_file = str(file_path.relative_to(self.workspace_dir))
        except ValueError:
            rel_file = str(file_path)

        for idx, line in enumerate(lines):
            if len(line) > 1000:
                continue

            for rule in applicable_rules:
                if rule.pattern.search(line):
                    if rule.not_match and rule.not_match.search(line):
                        continue
                    confirmed = True
                    if rule.source_pattern:
                        window_start = max(0, idx - 15)
                        window_text = "\n".join(lines[window_start:idx + 1])
                        confirmed = bool(rule.source_pattern.search(window_text))

                    if confirmed:
                        findings.append(Finding(
                            id=rule.id,
                            cwe=rule.cwe,
                            category=rule.category,
                            severity=rule.severity,
                            file=rel_file,
                            line=idx + 1,
                            snippet=line.strip(),
                            message=rule.message,
                            remediation=rule.remediation
                        ))
        return True

    def scan(
        self,
        target_path: str = ".",
        min_severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "ALL"] = "ALL"
    ) -> ScanResult:
        full_target = (self.workspace_dir / target_path).resolve()
        if not full_target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target_path}")

        min_rank = 1 if min_severity == "ALL" else SEVERITY_RANKS.get(min_severity, 1)
        ignore_dirs = {"node_modules", ".git", "dist", "build", "vendor", ".next", "target", "coverage", "__pycache__", ".venv", "venv"}

        scanned_count = 0
        findings: List[Finding] = []
        rules_by_lang: Dict[str, List[Any]] = {}

        if full_target.is_file():
            if self._scan_single_file(full_target, rules_by_lang, min_rank, findings):
                scanned_count += 1
        else:
            for root, dirs, files in os.walk(full_target):
                dirs[:] = [d for d in dirs if d not in ignore_dirs]
                for file_name in files:
                    if self._scan_single_file(Path(root) / file_name, rules_by_lang, min_rank, findings):
                        scanned_count += 1

        summary = {
            "critical": len([f for f in findings if f.severity == "CRITICAL"]),
            "high": len([f for f in findings if f.severity == "HIGH"]),
            "medium": len([f for f in findings if f.severity == "MEDIUM"]),
            "low": len([f for f in findings if f.severity == "LOW"])
        }

        return ScanResult(
            total_files_scanned=scanned_count,
            findings=findings,
            summary=summary
        )

    def format_cli_report(self, result: ScanResult) -> str:
        if not result.findings:
            return f"Wide Security Scan complete: 0 vulnerabilities found in {result.total_files_scanned} files scanned."

        lines = [
            f"Wide Security Scan: Found {len(result.findings)} issue(s) across {result.total_files_scanned} scanned files.",
            f"Summary: [CRITICAL: {result.summary['critical']}] [HIGH: {result.summary['high']}] [MEDIUM: {result.summary['medium']}] [LOW: {result.summary['low']}]\n"
        ]

        for f in result.findings:
            lines.append(f"[{f.severity}] {f.category} ({f.cwe}) in {f.file}:{f.line}")
            lines.append(f"  Message:     {f.message}")
            lines.append(f"  Code:        {f.snippet}")
            lines.append(f"  Remediation: {f.remediation}\n")

        return "\n".join(lines)
