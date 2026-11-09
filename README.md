<p align="center">
  <img src="assets/wide-logo.png" alt="Wide SDK" width="128">
  <h1 align="center">Wide SDK</h1>
  <p align="center">Python SDK to build autonomous AI coding and web security agents powered by Wide</p>
</p>

<p align="center">
  <a href="https://github.com/sl4de0day/wide-sdk/releases/latest">Download</a> ·
  <a href="#installation">Build</a> ·
  <a href="https://github.com/sl4de0day/wide-sdk/releases">Changelog</a> ·
  <a href="https://github.com/sl4de0day/wide-ide">Wide IDE</a> ·
  <a href="https://github.com/sl4de0day/wide-cli">Wide CLI</a> ·
  <a href="https://github.com/sl4de0day/wide-app">Wide App</a> ·
  <a href="https://github.com/sl4de0day/wide-action">Wide Action</a> ·
  <a href="https://github.com/sl4de0day/wide-rules">Wide Rules</a> ·
  <a href="LICENSE">License</a>
</p>

---

## Overview

Wide SDK allows Python developers to programmatically build, customize, and orchestrate autonomous AI coding and penetration testing agents with native Wide security tooling.

- **Autonomous Agent Loop:** Full ReAct (Reasoning and Action) loop with dynamic context compaction and execution limits.
- **Native SAST Engine:** Programmatic access to Wide's 20+ vulnerability inspection rules (SQLi, XSS, SSRF, Command Injection, XXE, Deserialization, Hardcoded Secrets).
- **Security Fuzzing and Payloads:** Built-in web endpoint fuzzer and attack vector generator for automated verification.
- **Multi-Provider Architecture:** Pluggable LLM backends supporting Ollama (local offline), Google Gemini, Anthropic Claude, and OpenAI/DeepSeek.
- **Custom Tool Ecosystem:** Extensible `@tool` interface with automatic JSON Schema generation from Python function signatures and type hints.

## Installation

```bash
pip install wide-sdk
```

## Quick Start

```python
from wide_sdk import Agent, GeminiProvider

provider = GeminiProvider(api_key="YOUR_GEMINI_API_KEY")
agent = Agent(provider=provider, working_directory=".")

response = agent.run("Scan this project for SQL injection vulnerabilities and fix any confirmed issues.")
print(response)
```

## Security Scanner API

Run Wide's comprehensive static analysis engine directly in Python:

```python
from wide_sdk.security import SecurityScanner

scanner = SecurityScanner(workspace_dir=".")
results = scanner.scan(min_severity="HIGH")

for finding in results.findings:
    print(f"[{finding.severity}] {finding.category} in {finding.file}:{finding.line}")
    print(f"Issue: {finding.message}")
    print(f"Remediation: {finding.remediation}\n")
```

## Active Fuzzer API

Automatically probe an API endpoint parameter:

```python
from wide_sdk.security import fuzz_endpoint

report = fuzz_endpoint(
    url="http://localhost:3000/api/search",
    param="q",
    payload_type="sqli"
)

if report.is_vulnerable:
    print(f"Vulnerability confirmed on {report.param}!")
```

## Configuration

Set up environment variables for your preferred provider:

```bash
export GEMINI_API_KEY="your-gemini-key"
export ANTHROPIC_API_KEY="your-claude-key"
export OPENAI_API_KEY="your-openai-key"
export DEEPSEEK_API_KEY="your-deepseek-key"
```

## License
GPL-3.0-or-later sl4de
