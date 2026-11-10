import re
from dataclasses import dataclass
from typing import List, Optional, Pattern

@dataclass
class SecurityRule:
    id: str
    cwe: str
    category: str
    severity: str
    languages: List[str]
    pattern: Pattern
    source_pattern: Optional[Pattern]
    message: str
    remediation: str

SECURITY_RULES: List[SecurityRule] = [
    SecurityRule(
        id="WIDE-SEC-001",
        cwe="CWE-89",
        category="SQL Injection",
        severity="CRITICAL",
        languages=["js", "ts", "py", "php", "java", "cs", "go", "rb"],
        pattern=re.compile(r"(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*?(?:\+|%s|\$|\.format\(|f['\"]).*?(?:req\.|params|body|query|input|\$_(?:GET|POST|REQUEST)|request\.)", re.IGNORECASE),
        source_pattern=re.compile(r"(?:req\.(?:query|params|body)|request\.(?:args|form|GET|POST)|\$_(?:GET|POST))", re.IGNORECASE),
        message="Dynamic SQL query constructed with unescaped user input.",
        remediation="Use parameterized queries or prepared statements."
    ),
    SecurityRule(
        id="WIDE-SEC-002",
        cwe="CWE-78",
        category="Command Injection",
        severity="CRITICAL",
        languages=["js", "ts", "py", "php", "java", "cs", "go", "rb"],
        pattern=re.compile(r"(?:child_process|exec|execSync|spawn|subprocess\.Popen|subprocess\.run|os\.system|shell_exec|system|passthru|Runtime\.getRuntime\(\)\.exec)\s*\(\s*(?:`[^`]*\$\{|['\"].*?\+\s*|f['\"][^'\"]*\{)", re.IGNORECASE),
        source_pattern=re.compile(r"(?:req\.|request\.|input|param|\$_)", re.IGNORECASE),
        message="System command execution sink receives unescaped parameters.",
        remediation="Avoid passing user input to shell commands. Use argument arrays without invoking a subshell."
    ),
    SecurityRule(
        id="WIDE-SEC-003",
        cwe="CWE-79",
        category="Cross-Site Scripting (XSS)",
        severity="HIGH",
        languages=["js", "ts", "php"],
        pattern=re.compile(r"(?:innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML|v-html|\becho\s+\$_(?:GET|POST)|print\s+\$_)\s*(?:=|\()\s*(?:.*?\b(?:query|param|body|req|location|search|URLSearchParams)\b)", re.IGNORECASE),
        source_pattern=None,
        message="Unsanitized user input rendered directly into the DOM or HTML output.",
        remediation="Use textContent or framework-safe bindings. Sanitize HTML using DOMPurify before rendering."
    ),
    SecurityRule(
        id="WIDE-SEC-004",
        cwe="CWE-918",
        category="Server-Side Request Forgery (SSRF)",
        severity="HIGH",
        languages=["js", "ts", "py", "php", "go", "java"],
        pattern=re.compile(r"(?:fetch|axios\.(?:get|post|request)|http\.get|urllib\.request|requests\.(?:get|post)|curl_exec)\s*\(\s*(?:req\.|params|query|body|request\.)", re.IGNORECASE),
        source_pattern=None,
        message="Outbound HTTP request targeting a user-supplied URL without destination validation.",
        remediation="Validate destination URLs against an explicit domain allowlist and block private IP ranges."
    ),
    SecurityRule(
        id="WIDE-SEC-005",
        cwe="CWE-22",
        category="Path Traversal",
        severity="HIGH",
        languages=["js", "ts", "py", "php", "java", "go"],
        pattern=re.compile(r"(?:readFile|readFileSync|createReadStream|open|file_get_contents|readfile|FileInputStream)\s*\(\s*(?:.*?path\.join.*?req\.|.*?\+\s*(?:req\.|params|query|\$_)|f['\"].*?\{request)", re.IGNORECASE),
        source_pattern=None,
        message="File system access with untrusted path concatenation vulnerable to directory traversal.",
        remediation="Resolve the path with Path.resolve() and verify that it starts with the intended base directory."
    ),
    SecurityRule(
        id="WIDE-SEC-006",
        cwe="CWE-502",
        category="Insecure Deserialization",
        severity="CRITICAL",
        languages=["js", "ts", "py", "php", "java"],
        pattern=re.compile(r"(?:pickle\.loads|yaml\.load\([^,)]+\)|unserialize\s*\(|node-serialize|serialize\.unserialize|XMLDecoder|ObjectInputStream)", re.IGNORECASE),
        source_pattern=None,
        message="Untrusted deserialization can lead to arbitrary code execution.",
        remediation="Never deserialize untrusted input with unsafe serializers. Use JSON, PyYAML safe_load, or cryptographic signing."
    ),
    SecurityRule(
        id="WIDE-SEC-007",
        cwe="CWE-611",
        category="XML External Entity (XXE)",
        severity="HIGH",
        languages=["js", "ts", "py", "php", "java"],
        pattern=re.compile(r"(?:xml2js|DOMParser|SimpleXMLElement|libxml_disable_entity_loader\s*\(\s*false|DocumentBuilderFactory.*?setFeature.*?external-general-entities.*?true)", re.IGNORECASE),
        source_pattern=None,
        message="XML parser configured without disabling external entity resolution.",
        remediation="Disable external DTDs and entity expansion in XML parsers."
    ),
    SecurityRule(
        id="WIDE-SEC-008",
        cwe="CWE-798",
        category="Hardcoded Secret",
        severity="HIGH",
        languages=["all"],
        pattern=re.compile(r"(?:(?:api_?key|secret|password|access_?token|jwt_?secret|private_?key)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.]{16,}['\"]|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|AIza[0-9A-Za-z\-_]{35})", re.IGNORECASE),
        source_pattern=None,
        message="High-entropy API token, private key, or credential hardcoded in source.",
        remediation="Extract secrets to environment variables or an external secret manager."
    ),
    SecurityRule(
        id="WIDE-SEC-009",
        cwe="CWE-327",
        category="Broken Cryptography",
        severity="MEDIUM",
        languages=["js", "ts", "py", "php", "java", "cs", "go"],
        pattern=re.compile(r"(?:createHash\s*\(\s*['\"](?:md5|sha1)['\"]|hashlib\.(?:md5|sha1)|MD5\.Create|DES|RC4|crypto\.createCipheriv\s*\(\s*['\"][^'\"]*ecb)", re.IGNORECASE),
        source_pattern=None,
        message="Collision-prone or deprecated cryptographic algorithm (MD5/SHA1/DES/ECB mode).",
        remediation="Use SHA-256 for integrity, bcrypt/argon2 for passwords, and AES-256-GCM for symmetric encryption."
    ),
    SecurityRule(
        id="WIDE-SEC-010",
        cwe="CWE-94",
        category="Code Injection (eval)",
        severity="CRITICAL",
        languages=["js", "ts", "py", "php"],
        pattern=re.compile(r"(?:\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['\"`]|setInterval\s*\(\s*['\"`])", re.IGNORECASE),
        source_pattern=re.compile(r"(?:req\.|params|query|input|\$_)", re.IGNORECASE),
        message="Dynamic code evaluation sink called with user-influenced string.",
        remediation="Remove eval and dynamic Function calls. Refactor logic to use structured mappings."
    ),
    SecurityRule(
        id="WIDE-SEC-011",
        cwe="CWE-1333",
        category="Regular Expression Denial of Service (ReDoS)",
        severity="MEDIUM",
        languages=["js", "ts", "py", "java"],
        pattern=re.compile(r"/(?:[a-zA-Z0-9_]*\+)+[a-zA-Z0-9_]*\+", re.IGNORECASE),
        source_pattern=None,
        message="Catastrophic backtracking vulnerability detected in nested regex quantifier.",
        remediation="Refactor regex to eliminate overlapping nested repetitions or enforce length limits."
    ),
    SecurityRule(
        id="WIDE-SEC-012",
        cwe="CWE-1321",
        category="Prototype Pollution",
        severity="HIGH",
        languages=["js", "ts"],
        pattern=re.compile(r"(?:__proto__|constructor\s*\[\s*['\"]prototype['\"]\]|Object\.assign\s*\(\s*\{\}\s*,\s*(?:req\.|body|params)|merge\s*\([^,]+,\s*(?:req\.|body))", re.IGNORECASE),
        source_pattern=None,
        message="Potential prototype pollution via unsafe recursive object merging.",
        remediation="Validate keys against '__proto__' and 'constructor', or use Object.create(null)."
    ),
    SecurityRule(
        id="WIDE-SEC-013",
        cwe="CWE-943",
        category="NoSQL Injection",
        severity="CRITICAL",
        languages=["js", "ts", "py"],
        pattern=re.compile(r"(?:\.find|\.findOne|\.deleteMany|\.updateMany)\s*\(\s*(?:req\.(?:body|query|params)|\{[^}]*\$(?:where|ne|gt|regex))", re.IGNORECASE),
        source_pattern=None,
        message="NoSQL query structure accepts raw user object without type coercion.",
        remediation="Enforce strict schema validation and sanitize inputs so operator objects cannot be injected."
    ),
    SecurityRule(
        id="WIDE-SEC-014",
        cwe="CWE-601",
        category="Open Redirect",
        severity="MEDIUM",
        languages=["js", "ts", "py", "php"],
        pattern=re.compile(r"(?:res\.redirect|redirect|header\s*\(\s*['\"]Location:)\s*\(\s*(?:req\.|params|query|request\.)", re.IGNORECASE),
        source_pattern=None,
        message="HTTP redirection destination is controlled by untrusted request parameter.",
        remediation="Use relative redirect paths or validate destinations against an explicit domain allowlist."
    ),
    SecurityRule(
        id="WIDE-SEC-015",
        cwe="CWE-384",
        category="Session Fixation",
        severity="MEDIUM",
        languages=["js", "ts", "py", "php"],
        pattern=re.compile(r"(?:session\.regenerate|session_regenerate_id)\s*===?\s*false|req\.session\.regenerate\s*\(\s*function\s*\(\)\s*\{\s*\}\s*\)", re.IGNORECASE),
        source_pattern=None,
        message="Session identifier not refreshed upon privilege escalation or authentication.",
        remediation="Always regenerate session identifiers upon login."
    ),
    SecurityRule(
        id="WIDE-SEC-016",
        cwe="CWE-639",
        category="Insecure Direct Object Reference (IDOR)",
        severity="HIGH",
        languages=["js", "ts", "py", "php", "java"],
        pattern=re.compile(r"(?:findById|findByPk|findOne|SELECT.*?WHERE id =)\s*\(\s*req\.params\.id\s*\)(?!.*?(?:userId|ownerId|user\._?id|req\.user))", re.IGNORECASE),
        source_pattern=None,
        message="Database record queried strictly by client-supplied ID without verifying ownership.",
        remediation="Scope database queries to the authenticated user ID."
    ),
    SecurityRule(
        id="WIDE-SEC-017",
        cwe="CWE-942",
        category="CORS Misconfiguration",
        severity="MEDIUM",
        languages=["js", "ts", "py", "php"],
        pattern=re.compile(r"(?:Access-Control-Allow-Origin.*?['\"]\*['\"].*?Access-Control-Allow-Credentials.*?['\"]true['\"]|cors\s*\(\s*\{\s*origin:\s*true\s*,\s*credentials:\s*true)", re.IGNORECASE),
        source_pattern=None,
        message="Wildcard CORS origin allowed in conjunction with credential sharing.",
        remediation="Never combine Access-Control-Allow-Credentials: true with a wildcard origin."
    ),
    SecurityRule(
        id="WIDE-SEC-018",
        cwe="CWE-352",
        category="Cross-Site Request Forgery (CSRF)",
        severity="MEDIUM",
        languages=["js", "ts", "py", "php"],
        pattern=re.compile(r"(?:app\.(?:post|put|delete|patch)\s*\([^,]+,\s*(?!.*?csrf).*?\bfunction\b|csrfProtection.*?enabled:\s*false)", re.IGNORECASE),
        source_pattern=None,
        message="State-changing HTTP route registered without apparent CSRF token protection.",
        remediation="Enable SameSite cookie attributes and use anti-CSRF tokens."
    ),
    SecurityRule(
        id="WIDE-SEC-019",
        cwe="CWE-330",
        category="Weak Randomness",
        severity="LOW",
        languages=["js", "ts", "py", "php", "java"],
        pattern=re.compile(r"(?:Math\.random|random\.random|rand\(|mt_rand)\s*\(\s*\).*?(?:token|secret|session|key|nonce|auth|otp)", re.IGNORECASE),
        source_pattern=None,
        message="Pseudorandom generator used for security-sensitive token generation.",
        remediation="Use cryptographically secure random number generators (secrets.token_hex())."
    ),
    SecurityRule(
        id="WIDE-SEC-020",
        cwe="CWE-209",
        category="Information Leakage",
        severity="LOW",
        languages=["js", "ts", "py", "php", "java"],
        pattern=re.compile(r"(?:res\.(?:send|json)\s*\(\s*(?:err\.stack|err\.message|error\.stack)|printStackTrace\s*\(\)|ini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*['\"]1['\"]\))", re.IGNORECASE),
        source_pattern=None,
        message="Detailed internal error stack trace or debug information exposed to client.",
        remediation="Log stack traces internally and return generic error responses to clients."
    )
]

DEFAULT_AGENT_RULES: List[SecurityRule] = [
    SecurityRule(
        id="wide/cwe078-ai-unsafe-tool-exec",
        cwe="CWE-78",
        category="AI_SECURITY",
        severity="CRITICAL",
        languages=["js", "jsx", "ts", "tsx", "py", "mjs", "cjs"],
        pattern=re.compile(r"\b(?:exec|execSync|spawn|subprocess\.run|os\.system)\s*\(\s*(?:toolCall|tool_call|args|arguments|response\.command|patch\.command)", re.IGNORECASE),
        source_pattern=None,
        message="Executing raw system command directly from AI tool call response without argument validation.",
        remediation="Whitelist allowed commands and run them in an isolated sandbox with fixed arguments."
    ),
    SecurityRule(
        id="wide/cwe079-ai-prompt-injection",
        cwe="CWE-79",
        category="AI_SECURITY",
        severity="HIGH",
        languages=["js", "jsx", "ts", "tsx", "py", "mjs", "cjs"],
        pattern=re.compile(r"\b(?:prompt|instruction|query|input)\s*[:=]\s*(?:f?[\"'].*?\{|`.*?$\{).*(?:req\.|params\.|body\.|userInput|user_input|request\.)", re.IGNORECASE),
        source_pattern=None,
        message="Untrusted user input concatenated directly into LLM prompt template without sanitization.",
        remediation="Use structured multi-turn message roles or sanitize prompt inputs before sending to the model."
    ),
    SecurityRule(
        id="wide/cwe095-ai-unconstrained-eval",
        cwe="CWE-95",
        category="AI_SECURITY",
        severity="CRITICAL",
        languages=["js", "jsx", "ts", "tsx", "py", "mjs", "cjs"],
        pattern=re.compile(r"\b(?:eval|Function|vm\.runInContext|compile)\s*\(\s*(?:toolOutput|tool_output|response\.text|aiResult|ai_output|completion)", re.IGNORECASE),
        source_pattern=None,
        message="Evaluating raw executable code returned by LLM without sandboxing or static verification.",
        remediation="Parse responses into structured abstract syntax trees or validate against a strict AST schema before execution."
    ),
    SecurityRule(
        id="wide/cwe306-ai-unauthenticated-mcp-registration",
        cwe="CWE-306",
        category="AI_SECURITY",
        severity="HIGH",
        languages=["js", "jsx", "ts", "tsx", "py", "mjs", "cjs"],
        pattern=re.compile(r"\b(?:registerMcpServer|addMcpServer|mcpClient\.connect)\s*\(\s*(?:url|endpoint|serverConfig)\s*\)", re.IGNORECASE),
        source_pattern=None,
        message="Model Context Protocol server registered without identity verification or authorization signature.",
        remediation="Verify server host authorization and enforce cryptographic signature checks prior to registering external toolsets."
    ),
    SecurityRule(
        id="wide/cwe400-ai-unbounded-agent-loop",
        cwe="CWE-400",
        category="AI_SECURITY",
        severity="MEDIUM",
        languages=["js", "jsx", "ts", "tsx", "py", "mjs", "cjs"],
        pattern=re.compile(r"while\s*\(\s*(?:true|1|!done|!finished|!settled)\s*\)\s*\{(?![^}]*\b(?:maxRounds|maxSteps|maxIterations|round\s*>=|step\s*>=)\b)", re.IGNORECASE),
        source_pattern=None,
        message="Autonomous agent execution loop lacks explicit termination boundary or maximum step limit.",
        remediation="Enforce a strict step threshold or cancellation budget to prevent runaway agent execution loops."
    ),
    SecurityRule(
        id="wide/cwe770-ai-unbounded-context-accumulation",
        cwe="CWE-770",
        category="AI_SECURITY",
        severity="MEDIUM",
        languages=["js", "jsx", "ts", "tsx", "py", "mjs", "cjs"],
        pattern=re.compile(r"\b(?:history|messages|chatContext)\.push\s*\(.*?\)(?![^;]*(?:slice|shift|trim|truncate|maxTokens|maxHistory))", re.IGNORECASE),
        source_pattern=None,
        message="LLM conversation context accumulates without token limits or sliding window truncation.",
        remediation="Prune chat context using sliding window truncation or token counting before appending turns."
    ),
    SecurityRule(
        id="wide/cwe798-ai-prompt-secret-leak",
        cwe="CWE-798",
        category="AI_SECURITY",
        severity="HIGH",
        languages=["js", "jsx", "ts", "tsx", "py", "mjs", "cjs"],
        pattern=re.compile(r"\b(?:systemPrompt|systemMessage|system_prompt)\s*[:=].*?(?:process\.env\.(?:[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASS|AUTH))|apiKey|api_key|secret)", re.IGNORECASE),
        source_pattern=None,
        message="Sensitive secrets or private API credentials embedded in prompt context.",
        remediation="Strip private credentials from prompt text and provide secrets through isolated backend proxy channels."
    ),
    SecurityRule(
        id="wide/cwe829-ai-unvalidated-patch-apply",
        cwe="CWE-829",
        category="AI_SECURITY",
        severity="HIGH",
        languages=["js", "jsx", "ts", "tsx", "py", "mjs", "cjs"],
        pattern=re.compile(r"\b(?:applyPatch|gitApply|applyDiff|writePatch)\s*\(\s*(?:aiPatch|llmResponse|output\.patch|modelDiff)", re.IGNORECASE),
        source_pattern=None,
        message="Applying LLM-generated patch directly to codebase without path traversal or integrity checks.",
        remediation="Validate destination file paths are strictly within workspace bounds and run static scans before applying patches."
    )
]
