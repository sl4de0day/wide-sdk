import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from ..types import Finding

MANIFEST_NAMES: Set[str] = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "poetry.lock",
    "pipfile.lock",
    "go.mod",
    "cargo.toml",
    "cargo.lock",
    "composer.lock",
    "gemfile.lock",
    "pom.xml",
}

IGNORED_DIRS: Set[str] = {
    "node_modules", ".git", "dist", "build", "vendor", ".next",
    "target", "coverage", "__pycache__", ".venv", "venv", ".gemini", ".vscode",
}


def _clean_version_parts(raw: str) -> List[int]:
    cleaned = re.sub(r"^[vV^~=<>\s]+", "", str(raw or "").strip())
    cleaned = re.split(r"[-+\s]", cleaned)[0]
    if not cleaned:
        return []
    parts: List[int] = []
    for part in cleaned.split("."):
        m = re.match(r"^(\d+)", part)
        parts.append(int(m.group(1)) if m else 0)
    return parts


def compare_versions(a: str, b: str) -> int:
    pa = _clean_version_parts(a)
    pb = _clean_version_parts(b)
    length = max(len(pa), len(pb))
    for i in range(length):
        va = pa[i] if i < len(pa) else 0
        vb = pb[i] if i < len(pb) else 0
        if va > vb:
            return 1
        if va < vb:
            return -1
    return 0


def is_version_affected(version: str, adv: Dict[str, Any]) -> bool:
    if not version or re.match(r"^(?:\*|latest|workspace:)", version, re.IGNORECASE):
        return False
    stripped = re.sub(r"^[vV^~=<>]+", "", version)
    if not re.match(r"^\d", stripped):
        return False
    ge = adv.get("ge")
    lt = adv.get("lt")
    le = adv.get("le")
    if ge and compare_versions(version, str(ge)) < 0:
        return False
    if lt and compare_versions(version, str(lt)) >= 0:
        return False
    if le and compare_versions(version, str(le)) > 0:
        return False
    return bool(lt or le or ge)


def _find_line(lines: List[str], token: str) -> int:
    lower = token.lower()
    for i, line in enumerate(lines):
        if lower in line.lower():
            return i + 1
    return 1


def parse_manifest_dependencies(file_path: str, content: str) -> List[Tuple[str, str, str, int, str]]:
    base = Path(file_path).name.lower()
    lines = content.splitlines()
    deps: List[Tuple[str, str, str, int, str]] = []
    seen: Set[str] = set()

    def push_dep(eco: str, name: str, raw_ver: str, line: int, snippet: str) -> None:
        clean_ver = re.sub(r"^[~^>=<\s]+", "", str(raw_ver or "").strip()).split()[0] if str(raw_ver or "").strip() else ""
        if not name or not clean_ver or re.match(r"^(?:\*|latest|workspace:|file:|git\+|https?:)", clean_ver, re.IGNORECASE):
            return
        if not re.search(r"\d", clean_ver):
            return
        key = f"{eco}:{name.lower()}@{clean_ver}:{line}"
        if key in seen:
            return
        seen.add(key)
        deps.append((eco, name, clean_ver, line, snippet.strip()))

    if base == "package.json":
        try:
            pkg = json.loads(content)
            for sec in ("dependencies", "devDependencies", "optionalDependencies"):
                sec_map = pkg.get(sec)
                if isinstance(sec_map, dict):
                    for name, ver in sec_map.items():
                        if isinstance(ver, str):
                            ln = _find_line(lines, f'"{name}"')
                            push_dep("npm", name, ver, ln, lines[ln - 1] if ln - 1 < len(lines) else f'"{name}": "{ver}"')
        except Exception:
            pass
        return deps

    if base == "package-lock.json":
        try:
            lock = json.loads(content)
            pkgs = lock.get("packages")
            if isinstance(pkgs, dict):
                for pkg_path, info in pkgs.items():
                    if isinstance(info, dict) and isinstance(info.get("version"), str):
                        pkg_name = pkg_path.split("node_modules/")[-1]
                        if pkg_name:
                            ln = _find_line(lines, f'"{pkg_path}"')
                            push_dep("npm", pkg_name, info["version"], ln, lines[ln - 1] if ln - 1 < len(lines) else pkg_name)
        except Exception:
            pass
        return deps

    if base == "yarn.lock":
        current_pkgs: List[str] = []
        for idx, line in enumerate(lines):
            t = line.strip()
            if re.match(r'^[^\s#"][^:\n]*:$', t) or re.match(r'^"[^"]+.*":$', t):
                current_pkgs = []
                for spec in t.rstrip(":").split(","):
                    cleaned = spec.strip().strip("\"'")
                    at_idx = cleaned.rfind("@")
                    if at_idx > 0:
                        current_pkgs.append(cleaned[:at_idx])
                continue
            vm = re.match(r'^\s+version\s+(?:"([^"]+)"|\'([^\']+)\'|([^\s]+))', line)
            if vm and current_pkgs:
                ver = vm.group(1) or vm.group(2) or vm.group(3)
                for name in current_pkgs:
                    push_dep("npm", name, ver, idx + 1, line)
                current_pkgs = []
        return deps

    if base == "pnpm-lock.yaml":
        for idx, line in enumerate(lines):
            m = re.match(r"^\s{2,4}'?/?(@?[^/\s':]+(?:/[^@\s(':]+)?)[@/]([0-9][0-9A-Za-z.\-+]*)", line)
            if m:
                push_dep("npm", m.group(1), m.group(2), idx + 1, line)
        return deps

    if base == "requirements.txt":
        for idx, line in enumerate(lines):
            if re.match(r"^\s*#", line):
                continue
            m = re.match(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]+\])?\s*(?:==|>=|~=)\s*([0-9][0-9A-Za-z.\-]*)", line)
            if m:
                push_dep("pip", m.group(1), m.group(2), idx + 1, line)
        return deps

    if base == "poetry.lock":
        cur_name = ""
        cur_line = 1
        for idx, line in enumerate(lines):
            t = line.strip()
            nm = re.match(r'^name\s*=\s*"([^"]+)"', t)
            if nm:
                cur_name = nm.group(1)
                cur_line = idx + 1
                continue
            vm = re.match(r'^version\s*=\s*"([^"]+)"', t)
            if vm and cur_name:
                push_dep("pip", cur_name, vm.group(1), cur_line, f'{cur_name} = "{vm.group(1)}"')
                cur_name = ""
        return deps

    if base == "pipfile.lock":
        try:
            doc = json.loads(content)
            for sec in ("default", "develop"):
                sec_map = doc.get(sec)
                if isinstance(sec_map, dict):
                    for name, info in sec_map.items():
                        ver = re.sub(r"^==\s*", "", str((info or {}).get("version", "")))
                        if ver:
                            ln = _find_line(lines, f'"{name}"')
                            push_dep("pip", name, ver, ln, lines[ln - 1] if ln - 1 < len(lines) else name)
        except Exception:
            pass
        return deps

    if base == "go.mod":
        for idx, line in enumerate(lines):
            if re.match(r"^\s*//", line):
                continue
            m = re.match(r"^\s*(?:require\s+)?([A-Za-z0-9._~/-]+\.[A-Za-z0-9._~/-]+)\s+(v[0-9][0-9A-Za-z.\-+]*)", line)
            if m:
                push_dep("go", m.group(1), m.group(2), idx + 1, line)
        return deps

    if base == "cargo.lock":
        cur_name = ""
        cur_line = 1
        for idx, line in enumerate(lines):
            nm = re.match(r'^\s*name\s*=\s*"([^"]+)"', line)
            if nm:
                cur_name = nm.group(1)
                cur_line = idx + 1
                continue
            vm = re.match(r'^\s*version\s*=\s*"([^"]+)"', line)
            if vm and cur_name:
                push_dep("cargo", cur_name, vm.group(1), cur_line, f'{cur_name} = "{vm.group(1)}"')
                cur_name = ""
        return deps

    if base == "cargo.toml":
        section = ""
        for idx, line in enumerate(lines):
            t = line.strip()
            if not t or t.startswith("#"):
                continue
            sm = re.match(r"^\[([^\]]+)\]", t)
            if sm:
                section = sm.group(1).strip().lower()
                continue
            if not section.endswith("dependencies"):
                continue
            dm = re.match(r'^([A-Za-z0-9_-]+)\s*=\s*["\']([^"\']+)["\']', t)
            if dm:
                push_dep("cargo", dm.group(1), dm.group(2), idx + 1, t)
                continue
            im = re.match(r'^([A-Za-z0-9_-]+)\s*=\s*\{[^}]*\bversion\s*=\s*["\']([^"\']+)["\']', t)
            if im:
                push_dep("cargo", im.group(1), im.group(2), idx + 1, t)
        return deps

    if base == "composer.lock":
        try:
            doc = json.loads(content)
            for p in (doc.get("packages") or []) + (doc.get("packages-dev") or []):
                if isinstance(p, dict) and p.get("name") and p.get("version"):
                    ln = _find_line(lines, f'"{p["name"]}"')
                    push_dep("composer", str(p["name"]), str(p["version"]), ln, lines[ln - 1] if ln - 1 < len(lines) else str(p["name"]))
        except Exception:
            pass
        return deps

    if base == "gemfile.lock":
        for idx, line in enumerate(lines):
            m = re.match(r"^\s{4}([A-Za-z0-9_.-]+)\s+\(([0-9][0-9A-Za-z.-]*)\)", line)
            if m:
                push_dep("rubygems", m.group(1), m.group(2), idx + 1, line)
        return deps

    if base == "pom.xml":
        for m in re.finditer(r"<dependency\b[^>]*>([\s\S]*?)</dependency>", content, re.IGNORECASE):
            block = m.group(1)
            gid = re.search(r"<groupId>\s*([^<\s]+)\s*</groupId>", block, re.IGNORECASE)
            aid = re.search(r"<artifactId>\s*([^<\s]+)\s*</artifactId>", block, re.IGNORECASE)
            ver = re.search(r"<version>\s*([^<\s]+)\s*</version>", block, re.IGNORECASE)
            if gid and aid and ver and not ver.group(1).startswith("${"):
                ln = content[:m.start()].count("\n") + 1
                push_dep("maven", f"{gid.group(1)}:{aid.group(1)}", ver.group(1), ln, f"{aid.group(1)}:{ver.group(1)}")
                push_dep("maven", aid.group(1), ver.group(1), ln, f"{aid.group(1)}:{ver.group(1)}")
    return deps


def collect_imported_packages(content: str, imported: Set[str]) -> None:
    for m in re.finditer(r'(?:import\s+(?:[\s\S]{1,120}?\s+from\s+)?|require\s*\()\s*["\']([^"\']+)["\']', content):
        spec = m.group(1).strip()
        if not spec or spec.startswith("."):
            continue
        if spec.startswith("@"):
            parts = spec.split("/")
            imported.add(f"{parts[0]}/{parts[1]}".lower() if len(parts) >= 2 else spec.lower())
        else:
            imported.add(spec.split("/")[0].lower())
    for m in re.finditer(r"^\s*(?:from|import)\s+([A-Za-z0-9_.-]+)", content, re.MULTILINE):
        base = m.group(1).split(".")[0].lower()
        imported.add(base)
        imported.add(base.replace("_", "-"))
    for m in re.finditer(r'"([A-Za-z0-9._~/-]+\.[A-Za-z0-9._~/-]+)"', content):
        imported.add(m.group(1).lower())
    for m in re.finditer(r"^\s*(?:use|extern\s+crate)\s+([A-Za-z0-9_]+)", content, re.MULTILINE):
        crate = m.group(1).lower()
        imported.add(crate)
        imported.add(crate.replace("_", "-"))


def _norm_severity(raw: str) -> str:
    u = str(raw or "MEDIUM").upper()
    if u in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return u
    if u == "ERROR":
        return "HIGH"
    if u == "WARNING":
        return "MEDIUM"
    return "LOW"


def scan_workspace_dependencies(
    workspace_dir: Path,
    advisories: Dict[str, Any],
    min_rank: int,
    severity_ranks: Dict[str, int],
    imported_packages: Optional[Set[str]] = None,
) -> List[Finding]:
    if not isinstance(advisories, dict):
        return []
    manifests: List[Path] = []
    for root, dirs, files in os.walk(workspace_dir):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for fname in files:
            if fname.lower() in MANIFEST_NAMES:
                manifests.append(Path(root) / fname)

    if not manifests:
        return []

    imported = imported_packages or set()
    has_imports = len(imported) > 0
    findings: List[Finding] = []
    emitted: Set[str] = set()

    for full_path in manifests:
        try:
            if full_path.stat().st_size > 4 * 1024 * 1024:
                continue
            content = full_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        rel_path = str(full_path.relative_to(workspace_dir)).replace("\\", "/")
        deps = parse_manifest_dependencies(rel_path, content)
        for eco, name, ver, line, snippet in deps:
            eco_list = advisories.get(eco) or []
            if not isinstance(eco_list, list):
                continue
            dep_lower = name.lower()
            is_reachable = dep_lower in imported or (":" in dep_lower and dep_lower.split(":", 1)[1] in imported)

            for adv in eco_list:
                if not isinstance(adv, dict) or str(adv.get("name", "")).lower() != dep_lower:
                    continue
                if not is_version_affected(ver, adv):
                    continue
                sev = _norm_severity(adv.get("sev", "MEDIUM"))
                if severity_ranks.get(sev, 1) < min_rank:
                    continue
                adv_id = str(adv.get("id", "advisory"))
                dedup_key = f"{rel_path}:{line}:{adv_id}"
                if dedup_key in emitted:
                    continue
                emitted.add(dedup_key)

                tags: List[str] = []
                if has_imports:
                    tags.append("REACHABLE" if is_reachable else "INSTALLED")
                if adv.get("kev"):
                    tags.append("CISA KEV")
                if isinstance(adv.get("epss"), (int, float)) and adv["epss"] > 0:
                    tags.append(f"EPSS {adv['epss'] * 100:.1f}%")
                tag_suffix = f" [{' ,'.join(tags).replace(' ,', ', ')}]" if tags else ""
                fix = (
                    f"Upgrade {name} to version {adv['lt']} or later."
                    if adv.get("lt")
                    else f"Upgrade {name} to a version newer than {adv['le']}."
                    if adv.get("le")
                    else f"Upgrade {name} to a patched release."
                )

                findings.append(
                    Finding(
                        id=adv_id,
                        cwe=str(adv.get("cwe") or "CWE-1395"),
                        category="SCA",
                        severity=sev,  # type: ignore[arg-type]
                        file=rel_path,
                        line=line,
                        snippet=snippet,
                        message=f"{name}@{ver} is affected by {adv_id}{tag_suffix}: {adv.get('note') or 'known security advisory'}",
                        remediation=fix,
                        source="sca",
                        reachable=is_reachable if has_imports else None,
                    )
                )

    return findings
