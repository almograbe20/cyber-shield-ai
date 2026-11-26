"""
Static Analysis Engine — Cyber Shield AI
========================================
Scans source code line by line for known dangerous patterns.

In the MVP we use built-in (regex) rules so the app works immediately without
installing external tools. Later we add Semgrep / Bandit as extra result
sources, then pass everything to the AI layer (ai_analysis.py).

Each rule returns a Finding containing:
- id          : unique rule identifier
- title       : vulnerability title
- severity    : critical / high / medium / low
- cwe         : reference CWE id (global vulnerability taxonomy)
- line        : line number
- snippet     : matched code
- description + remediation come from the rule catalog
"""

import re
from dataclasses import dataclass, asdict
from typing import List, Optional


# ---------------------------------------------------------------------------
# Rule catalog: each rule = a pattern (regex) + educational metadata
# ---------------------------------------------------------------------------
@dataclass
class Rule:
    id: str
    title: str
    severity: str           # critical | high | medium | low
    cwe: str                # e.g. CWE-89
    pattern: str            # regular expression
    languages: List[str]    # applicable languages (["*"] = all)
    description: str        # what the vulnerability is
    remediation: str        # how to fix it
    flags: int = re.IGNORECASE


RULES: List[Rule] = [
    # ---------------- SQL Injection ----------------
    Rule(
        id="SQLI-001",
        title="Possible SQL Injection",
        severity="critical",
        cwe="CWE-89",
        pattern=r"""(execute|query|cursor\.execute|\.raw)\s*\(\s*["'].*?(\+|%|\.format|f["']).*?["']""",
        languages=["python", "javascript", "php", "java"],
        description="A SQL query is built by concatenating input into a string, letting an attacker inject malicious SQL commands.",
        remediation="Use parameterized queries (prepared statements) or an ORM instead of string concatenation.",
    ),
    Rule(
        id="SQLI-002",
        title="User input concatenated into SQL query",
        severity="critical",
        cwe="CWE-89",
        pattern=r"""(f["'][^"']*\b(SELECT|INSERT|UPDATE|DELETE)\b)|(\b(SELECT|INSERT|UPDATE|DELETE)\b.*["']\s*(\+|%|\.format|\$\{))|((\+|%|\.format|\$\{)\s*["'][^"']*\b(FROM|WHERE|VALUES|SET)\b)""",
        languages=["*"],
        description="A SQL query is assembled by concatenating text with variables (+, f-string or format) instead of safe parameters.",
        remediation="Separate data from the query using placeholders (?, %s) and pass values as parameters.",
    ),

    # ---------------- Command Injection ----------------
    Rule(
        id="CMDI-001",
        title="OS Command Injection",
        severity="critical",
        cwe="CWE-78",
        pattern=r"(os\.system|os\.popen|subprocess\.(call|run|Popen)|exec|child_process\.(exec|execSync))\s*\(",
        languages=["python", "javascript"],
        description="Executes operating-system commands using input that may be untrusted.",
        remediation="Avoid passing user input to commands. Use a fixed argument list with shell=False and validate input (allowlist).",
    ),
    Rule(
        id="EVAL-001",
        title="Dangerous use of eval / exec",
        severity="high",
        cwe="CWE-95",
        pattern=r"\beval\s*\(|\bexec\s*\(|new\s+Function\s*\(",
        languages=["python", "javascript"],
        description="eval/exec runs a string as code; if user input reaches it, this is a remote code execution flaw.",
        remediation="Remove eval/exec. If you need to parse data, use json.loads or a safe parser.",
    ),

    # ---------------- XSS ----------------
    Rule(
        id="XSS-001",
        title="Possible XSS via innerHTML / document.write",
        severity="high",
        cwe="CWE-79",
        pattern=r"(\.innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML)",
        languages=["javascript", "html"],
        description="Writing content directly into the page can allow a malicious script to run in the user's browser.",
        remediation="Use textContent, or an escaping library such as DOMPurify before inserting any content.",
    ),

    # ---------------- Hardcoded Secrets ----------------
    Rule(
        id="SECRET-001",
        title="Hardcoded secret / password in code",
        severity="high",
        cwe="CWE-798",
        pattern=r"""(api[_-]?key|secret|password|passwd|token|access[_-]?key)\s*[:=]\s*["'][^"'\s]{6,}["']""",
        languages=["*"],
        description="Sensitive data written directly in the code can leak through the repository.",
        remediation="Move secrets to environment variables or a secrets manager.",
    ),
    Rule(
        id="SECRET-002",
        title="Exposed AWS access key",
        severity="critical",
        cwe="CWE-798",
        pattern=r"AKIA[0-9A-Z]{16}",
        languages=["*"],
        description="An AWS access key id was found in the code.",
        remediation="Revoke the key immediately in AWS and use IAM roles or environment variables.",
    ),

    # ---------------- Weak Crypto ----------------
    Rule(
        id="CRYPTO-001",
        title="Weak hashing algorithm (MD5/SHA1)",
        severity="medium",
        cwe="CWE-327",
        pattern=r"(hashlib\.(md5|sha1)|MessageDigest\.getInstance\(\s*[\"'](MD5|SHA-?1)|createHash\(\s*[\"'](md5|sha1))",
        languages=["*"],
        description="MD5 and SHA1 are legacy algorithms and are not secure for passwords or signatures.",
        remediation="Use SHA-256 or stronger; for passwords use bcrypt / argon2 / PBKDF2.",
    ),

    # ---------------- Deserialization ----------------
    Rule(
        id="DESER-001",
        title="Insecure Deserialization",
        severity="high",
        cwe="CWE-502",
        pattern=r"(pickle\.loads|yaml\.load\s*\((?!.*Loader)|Marshal\.load)",
        languages=["python", "ruby"],
        description="Deserializing untrusted data can lead to remote code execution.",
        remediation="Use yaml.safe_load, avoid pickle with external data, and prefer JSON where possible.",
    ),

    # ---------------- Dangerous Configuration ----------------
    Rule(
        id="CONF-001",
        title="Debug mode enabled",
        severity="medium",
        cwe="CWE-489",
        pattern=r"(DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True)",
        languages=["python"],
        description="Running in debug mode in production exposes sensitive details and, in some frameworks, allows code execution.",
        remediation="Disable DEBUG in production and control it via an environment variable.",
    ),
    Rule(
        id="CONF-002",
        title="TLS certificate verification disabled",
        severity="high",
        cwe="CWE-295",
        pattern=r"(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|CERT_NONE)",
        languages=["*"],
        description="Disabling certificate verification opens the door to man-in-the-middle attacks.",
        remediation="Always enable certificate verification on encrypted connections.",
    ),

    # ---------------- Weak Randomness ----------------
    Rule(
        id="RAND-001",
        title="Insecure random number generator",
        severity="low",
        cwe="CWE-338",
        pattern=r"(random\.(random|randint|choice)|Math\.random)\s*\(",
        languages=["python", "javascript"],
        description="Standard random functions are not suitable for security (generating tokens/passwords).",
        remediation="Use secrets (Python) or crypto.randomBytes (Node) for security purposes.",
    ),
]


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    id: str
    title: str
    severity: str
    cwe: str
    line: int
    snippet: str
    description: str
    remediation: str
    # filled in later by the AI layer:
    ai_explanation: Optional[str] = None
    ai_confidence: Optional[str] = None


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def detect_language(filename: str, code: str) -> str:
    """Guess the code language from the extension or the content."""
    ext_map = {
        ".py": "python", ".js": "javascript", ".ts": "javascript",
        ".jsx": "javascript", ".tsx": "javascript", ".php": "php",
        ".java": "java", ".rb": "ruby", ".html": "html", ".go": "go",
    }
    if filename:
        for ext, lang in ext_map.items():
            if filename.lower().endswith(ext):
                return lang
    if re.search(r"\bdef\s+\w+\s*\(|\bimport\s+\w+", code):
        return "python"
    if re.search(r"\bfunction\b|=>|console\.log", code):
        return "javascript"
    return "unknown"


def scan_code(code: str, filename: str = "") -> dict:
    """Scan code text and return the findings + a statistical summary."""
    language = detect_language(filename, code)
    lines = code.splitlines()
    findings: List[Finding] = []

    for rule in RULES:
        if "*" not in rule.languages and language not in rule.languages:
            if language != "unknown":
                continue
        regex = re.compile(rule.pattern, rule.flags)
        for i, line in enumerate(lines, start=1):
            if regex.search(line):
                findings.append(Finding(
                    id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    cwe=rule.cwe,
                    line=i,
                    snippet=line.strip()[:200],
                    description=rule.description,
                    remediation=rule.remediation,
                ))

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.line))

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1

    # Simple security score (0-100): decreases with finding severity
    weights = {"critical": 25, "high": 12, "medium": 5, "low": 2}
    penalty = sum(weights.get(f.severity, 0) for f in findings)
    score = max(0, 100 - penalty)

    return {
        "language": language,
        "lines_scanned": len(lines),
        "total_findings": len(findings),
        "summary": summary,
        "security_score": score,
        "findings": [asdict(f) for f in findings],
    }


if __name__ == "__main__":
    sample = '''
import os
password = "SuperSecret123"
def run(cmd):
    os.system("ping " + cmd)
query = "SELECT * FROM users WHERE id = " + user_id
'''
    import json
    print(json.dumps(scan_code(sample, "test.py"), ensure_ascii=False, indent=2))
