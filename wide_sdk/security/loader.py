import os
import re
import json
import hashlib
import urllib.request
from pathlib import Path
from typing import List, Optional, Dict, Any
from .rules import SecurityRule, SECURITY_RULES, DEFAULT_AGENT_RULES

DEFAULT_CACHE_DIR = Path.home() / ".wide" / "rules"
DEFAULT_CACHE_FILE = DEFAULT_CACHE_DIR / "rules.json"
DEFAULT_OSV_FILE = DEFAULT_CACHE_DIR / "osv-bundle.json"
REMOTE_RULES_URL = "https://raw.githubusercontent.com/sl4de0day/wide-rules/main/dist/rules.json"
REMOTE_OSV_URL = "https://raw.githubusercontent.com/sl4de0day/wide-rules/main/dist/osv-bundle.json"
REMOTE_CHECKSUMS_URL = "https://raw.githubusercontent.com/sl4de0day/wide-rules/main/dist/SHA256SUMS"
INSTALL_WIDE_RULES = Path(__file__).resolve().parents[3] / "wide-rules" / "dist" / "rules.json"
INSTALL_WIDE_OSV = Path(__file__).resolve().parents[3] / "wide-rules" / "dist" / "osv-bundle.json"

_EMOJI_SINGLE = r"(?:[0-9#*]\uFE0F?\u20E3|[\U0001F1E6-\U0001FAFF\U0001F000-\U0001F0FF\U000E0020-\U000E007F]|[\u231A-\u23FF\u2600-\u27BF\u2B05-\u2B55][\uFE0E\uFE0F]?|[\u2139\u2194-\u21AA\u24C2\u25AA-\u25FE\u2934-\u2935\u3030\u303D\u3297\u3299]\uFE0F|[\uFE0E\uFE0F\u20E3])"
_EMOJI_ZWJ_RE = re.compile(rf"(?:{_EMOJI_SINGLE})(?:\u200D(?:{_EMOJI_SINGLE}))+")
_EMOJI_SINGLE_RE = re.compile(_EMOJI_SINGLE)


def _merge_default_agent_rules(rules: List[SecurityRule]) -> List[SecurityRule]:
    merged = list(rules)
    seen = {r.id for r in merged}
    for core in DEFAULT_AGENT_RULES:
        if core.id not in seen:
            merged.append(core)
            seen.add(core.id)
    merged.sort(key=lambda r: 0 if r.id == "wide/ai-no-emojis" else 1)
    return merged


class RuleLoader:
    @staticmethod
    def get_cache_path() -> Path:
        return DEFAULT_CACHE_FILE

    @staticmethod
    def get_agent_rules_path(workspace_dir: str = ".") -> Dict[str, Any]:
        ws_agent_path = (Path(workspace_dir) / ".wide" / "agent-rules.json").resolve()
        if ws_agent_path.exists():
            return {"active": str(ws_agent_path), "workspace": str(ws_agent_path), "cache": str(DEFAULT_CACHE_FILE)}
        ws_rules_path = (Path(workspace_dir) / ".wide" / "rules.json").resolve()
        if ws_rules_path.exists():
            return {"active": str(ws_rules_path), "workspace": str(ws_rules_path), "cache": str(DEFAULT_CACHE_FILE)}
        sibling_wide_rules = (Path(workspace_dir) / ".." / "wide-rules" / "dist" / "rules.json").resolve()
        if sibling_wide_rules.exists():
            return {"active": str(sibling_wide_rules), "workspace": None, "cache": str(DEFAULT_CACHE_FILE)}
        if INSTALL_WIDE_RULES.exists():
            return {"active": str(INSTALL_WIDE_RULES), "workspace": None, "cache": str(DEFAULT_CACHE_FILE)}
        if DEFAULT_CACHE_FILE.exists():
            return {"active": str(DEFAULT_CACHE_FILE), "workspace": None, "cache": str(DEFAULT_CACHE_FILE)}
        return {"active": "embedded", "workspace": None, "cache": str(DEFAULT_CACHE_FILE)}

    @classmethod
    def load_rules(
        cls,
        custom_path: Optional[str] = None,
        workspace_dir: str = "."
    ) -> List[SecurityRule]:
        if custom_path:
            p = (Path(workspace_dir) / custom_path).resolve()
            if p.exists():
                rules = cls._parse_file(p)
                if rules:
                    return rules

        ws_rules = (Path(workspace_dir) / ".wide" / "rules.json").resolve()
        if ws_rules.exists():
            rules = cls._parse_file(ws_rules)
            if rules:
                return rules

        sibling_wide_rules = (Path(workspace_dir) / ".." / "wide-rules" / "dist" / "rules.json").resolve()
        if sibling_wide_rules.exists():
            rules = cls._parse_file(sibling_wide_rules)
            if rules:
                return rules

        if INSTALL_WIDE_RULES.exists():
            rules = cls._parse_file(INSTALL_WIDE_RULES)
            if rules:
                return rules

        if DEFAULT_CACHE_FILE.exists():
            rules = cls._parse_file(DEFAULT_CACHE_FILE)
            if rules:
                return rules

        return list(SECURITY_RULES)

    @classmethod
    def load_agent_rules(
        cls,
        custom_path: Optional[str] = None,
        workspace_dir: str = "."
    ) -> List[SecurityRule]:
        if custom_path:
            p = (Path(workspace_dir) / custom_path).resolve()
            if p.exists():
                rules = cls._parse_file(p)
                filtered = [r for r in rules if r.category == "AI_SECURITY" or "ai-" in r.id]
                if filtered:
                    return filtered
                if rules:
                    return rules

        ws_agent_rules = (Path(workspace_dir) / ".wide" / "agent-rules.json").resolve()
        if ws_agent_rules.exists():
            rules = cls._parse_file(ws_agent_rules)
            if rules:
                return rules

        ws_rules = (Path(workspace_dir) / ".wide" / "rules.json").resolve()
        if ws_rules.exists():
            rules = cls._parse_file(ws_rules)
            filtered = [r for r in rules if r.category == "AI_SECURITY" or "ai-" in r.id]
            if filtered:
                return _merge_default_agent_rules(filtered)

        sibling_wide_rules = (Path(workspace_dir) / ".." / "wide-rules" / "dist" / "rules.json").resolve()
        if sibling_wide_rules.exists():
            rules = cls._parse_file(sibling_wide_rules)
            filtered = [r for r in rules if r.category == "AI_SECURITY" or "ai-" in r.id]
            if filtered:
                return _merge_default_agent_rules(filtered)

        if INSTALL_WIDE_RULES.exists():
            rules = cls._parse_file(INSTALL_WIDE_RULES)
            filtered = [r for r in rules if r.category == "AI_SECURITY" or "ai-" in r.id]
            if filtered:
                return _merge_default_agent_rules(filtered)

        if DEFAULT_CACHE_FILE.exists():
            rules = cls._parse_file(DEFAULT_CACHE_FILE)
            filtered = [r for r in rules if r.category == "AI_SECURITY" or "ai-" in r.id]
            if filtered:
                return _merge_default_agent_rules(filtered)

        return list(DEFAULT_AGENT_RULES)

    @classmethod
    def load_advisories(cls, workspace_dir: str = ".") -> Dict[str, Any]:
        candidates = [
            (Path(workspace_dir) / ".wide" / "osv.json").resolve(),
            DEFAULT_OSV_FILE,
            (Path(workspace_dir) / ".." / "wide-rules" / "dist" / "osv-bundle.json").resolve(),
            INSTALL_WIDE_OSV,
        ]
        for file_path in candidates:
            if file_path.exists():
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    continue
        return {"npm": [], "pip": [], "maven": [], "go": []}

    @classmethod
    def build_agent_instructions(cls, rules: Optional[List[SecurityRule]] = None) -> str:
        target_rules = rules if rules is not None and len(rules) > 0 else cls.load_agent_rules()
        lines: List[str] = []
        for r in target_rules:
            text = (r.instruction or r.message or "").strip()
            if text:
                lines.append(f"- {text}")
        return "\n".join(lines)

    @classmethod
    def sanitize_output(cls, text: str, rules: Optional[List[SecurityRule]] = None) -> str:
        if not text:
            return ""
        target_rules = rules if rules is not None and len(rules) > 0 else cls.load_agent_rules()
        result = _EMOJI_SINGLE_RE.sub("", _EMOJI_ZWJ_RE.sub("", text))
        for r in target_rules:
            if (r.id == "wide/ai-no-emojis" or "emoji" in r.id) and r.pattern:
                try:
                    result = r.pattern.sub("", result)
                except Exception:
                    pass
        return result

    @classmethod
    def update_rules(cls) -> int:
        DEFAULT_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        checksums: Dict[str, str] = {}
        try:
            sum_req = urllib.request.Request(
                REMOTE_CHECKSUMS_URL,
                headers={"User-Agent": "Wide-SDK/0.4141126"}
            )
            with urllib.request.urlopen(sum_req, timeout=15) as sum_res:
                for line in sum_res.read().decode("utf-8").splitlines():
                    m = re.match(r"^([a-fA-F0-9]{64})\s+\*?(.+)$", line.strip())
                    if m:
                        checksums[m.group(2).strip()] = m.group(1).lower()
        except Exception:
            pass

        req = urllib.request.Request(
            REMOTE_RULES_URL,
            headers={"User-Agent": "Wide-SDK/0.4141126"}
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            rules_raw = response.read().decode("utf-8")

        expected_sha = checksums.get("rules.json")
        if expected_sha:
            actual_sha = hashlib.sha256(rules_raw.encode("utf-8")).hexdigest()
            if actual_sha != expected_sha:
                raise ValueError("SHA-256 mismatch while downloading rules.json")

        data = json.loads(rules_raw)
        with open(DEFAULT_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        try:
            osv_req = urllib.request.Request(
                REMOTE_OSV_URL,
                headers={"User-Agent": "Wide-SDK/0.4141126"}
            )
            with urllib.request.urlopen(osv_req, timeout=15) as osv_res:
                osv_raw = osv_res.read().decode("utf-8")
            expected_osv = checksums.get("osv-bundle.json")
            if expected_osv:
                actual_osv = hashlib.sha256(osv_raw.encode("utf-8")).hexdigest()
                if actual_osv != expected_osv:
                    raise ValueError("SHA-256 mismatch while downloading osv-bundle.json")
            osv_data = json.loads(osv_raw)
            with open(DEFAULT_OSV_FILE, "w", encoding="utf-8") as f:
                json.dump(osv_data, f, indent=2)
        except ValueError:
            raise
        except Exception:
            pass

        rules_list = data if isinstance(data, list) else data.get("rules", [])
        return len(rules_list)

    @classmethod
    def _parse_file(cls, path: Path) -> List[SecurityRule]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            raw_list = data if isinstance(data, list) else data.get("rules", [])
            rules: List[SecurityRule] = []

            for item in raw_list:
                pattern_str = item.get("pattern")
                if not item.get("id") or not pattern_str:
                    continue
                try:
                    pat = re.compile(pattern_str, re.IGNORECASE)
                    src_str = item.get("source-pattern")
                    src_pat = re.compile(src_str, re.IGNORECASE) if src_str else None
                    nm_str = item.get("not-match") or item.get("notMatch")
                    nm_pat = re.compile(nm_str, re.IGNORECASE) if isinstance(nm_str, str) and nm_str else None

                    rules.append(
                        SecurityRule(
                            id=item["id"],
                            cwe=item.get("cwe", "N/A"),
                            category=item.get("category", "General Security"),
                            severity=item.get("severity", "MEDIUM"),
                            languages=item.get("languages", ["all"]),
                            pattern=pat,
                            source_pattern=src_pat,
                            message=item.get("message", ""),
                            remediation=item.get("remediation", ""),
                            instruction=item.get("instruction", item.get("message", "")),
                            not_match=nm_pat
                        )
                    )
                except Exception:
                    continue
            return rules
        except Exception:
            return []

def update_rules() -> int:
    return RuleLoader.update_rules()

def load_rules(custom_path: Optional[str] = None, workspace_dir: str = ".") -> List[SecurityRule]:
    return RuleLoader.load_rules(custom_path, workspace_dir)

def load_agent_rules(custom_path: Optional[str] = None, workspace_dir: str = ".") -> List[SecurityRule]:
    return RuleLoader.load_agent_rules(custom_path, workspace_dir)

def build_agent_instructions(rules: Optional[List[SecurityRule]] = None) -> str:
    return RuleLoader.build_agent_instructions(rules)

def sanitize_output(text: str, rules: Optional[List[SecurityRule]] = None) -> str:
    return RuleLoader.sanitize_output(text, rules)

def get_agent_rules_path(workspace_dir: str = ".") -> Dict[str, Any]:
    return RuleLoader.get_agent_rules_path(workspace_dir)

def load_advisories(workspace_dir: str = ".") -> Dict[str, Any]:
    return RuleLoader.load_advisories(workspace_dir)
