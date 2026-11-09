import sys
from wide_sdk.security import SecurityScanner

target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
scanner = SecurityScanner(workspace_dir=target_dir)

print(f"Initiating Wide Security Scan on: {target_dir}")
results = scanner.scan(min_severity="ALL")

print(f"Scan complete. Total files evaluated: {results.total_files_scanned}")
print(f"Summary: Critical={results.summary['critical']}, High={results.summary['high']}, Medium={results.summary['medium']}, Low={results.summary['low']}\n")

for f in results.findings:
    print(f"[{f.severity}] {f.category} ({f.cwe}) in {f.file}:{f.line}")
    print(f"  Issue:       {f.message}")
    print(f"  Code:        {f.snippet}")
    print(f"  Remediation: {f.remediation}\n")
