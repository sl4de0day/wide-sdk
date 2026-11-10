import os
import re
import json
import urllib.request
from pathlib import Path
from typing import List, Optional, Dict, Any
from .rules import SecurityRule, SECURITY_RULES, DEFAULT_AGENT_RULES

DEFAULT_CACHE_DIR = Path.home() / ".wide" / "rules"
DEFAULT_CACHE_FILE = DEFAULT_CACHE_DIR / "rules.json"
REMOTE_RULES_URL = "https://raw.githubusercontent.com/sl4de0day/wide-rules/main/dist/rules.json"

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
                return filtered

        if DEFAULT_CACHE_FILE.exists():
            rules = cls._parse_file(DEFAULT_CACHE_FILE)
            filtered = [r for r in rules if r.category == "AI_SECURITY" or "ai-" in r.id]
            if filtered:
                return filtered

        return list(DEFAULT_AGENT_RULES)

    @classmethod
    def update_rules(cls) -> int:
        DEFAULT_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(
            REMOTE_RULES_URL,
            headers={"User-Agent": "Wide-SDK/0.3101126"}
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))

        with open(DEFAULT_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

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
                            remediation=item.get("remediation", "")
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

def get_agent_rules_path(workspace_dir: str = ".") -> Dict[str, Any]:
    return RuleLoader.get_agent_rules_path(workspace_dir)
