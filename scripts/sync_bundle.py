import os
import shutil
from pathlib import Path

root_dir = Path(__file__).resolve().parent.parent
dist_env = os.environ.get("WIDE_RULES_DIST_DIR")
rules_dist = (root_dir / dist_env).resolve() if dist_env else (root_dir.parent / "wide-rules" / "dist").resolve()
rules_src = rules_dist / "rules.min.json"
osv_src = rules_dist / "osv-bundle.min.json"
conformance_src = rules_dist.parent / "engine" / "conformance" / "suite.json"
out_dir = root_dir / "wide_sdk" / "data"
conformance_out = root_dir / "tests" / "vendor" / "wide-engine" / "conformance.json"

if not rules_src.exists() or not osv_src.exists():
    raise SystemExit(f"Missing rules.min.json or osv-bundle.min.json in {rules_dist}")
if not conformance_src.exists():
    raise SystemExit(f"Missing engine conformance suite at {conformance_src}")

out_dir.mkdir(parents=True, exist_ok=True)
shutil.copy2(rules_src, out_dir / "rules.json")
shutil.copy2(osv_src, out_dir / "osv-bundle.json")
conformance_out.parent.mkdir(parents=True, exist_ok=True)
shutil.copy2(conformance_src, conformance_out)
print("Synced wide-rules offline bundle into wide_sdk/data/rules.json and wide_sdk/data/osv-bundle.json")
print("Synced wide-rules engine conformance suite into tests/vendor/wide-engine/conformance.json")
