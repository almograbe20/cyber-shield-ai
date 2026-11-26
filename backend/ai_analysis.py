"""
AI Layer — Cyber Shield AI (Hybrid System)
==========================================
Takes the raw findings from the scanner (scanner.py) and:
  1) Explains each vulnerability in simple language.
  2) Writes an executive summary for the whole scan.
  3) Estimates a confidence level to reduce false positives.

The system is HYBRID (per the project decision):
  - Current mode (MVP):  'mock'   -> generates a smart explanation from rule
                                     metadata, with no cost and no API key.
  - When a key is set:   'claude' -> calls the Claude API for real analysis.
  - At the same time: every finding is logged into dataset.jsonl so we can
    train our own model later. This is the "hybrid" contribution.

To switch to real mode later:
  1) Install the library:  pip install anthropic
  2) Set the key:          set ANTHROPIC_API_KEY=sk-...
  The code detects the key automatically and switches to 'claude' mode.
"""

import os
import json
import datetime
from pathlib import Path

# Load ANTHROPIC_API_KEY (and other settings) from a local .env file if present.
# The .env file is git-ignored and never committed. See .env.example.
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / ".env")
except ImportError:
    pass  # python-dotenv optional; env vars still work without it

DATASET_FILE = Path(__file__).parent / "dataset.jsonl"

_SEVERITY_LABEL = {
    "critical": "critical — fix immediately",
    "high": "high — fix very soon",
    "medium": "medium — plan to fix",
    "low": "low — nice improvement",
}


def ai_status() -> dict:
    """Reports the current AI mode (used by the UI/API)."""
    key = bool(os.getenv("ANTHROPIC_API_KEY"))
    lib = False
    try:
        import anthropic  # noqa: F401
        lib = True
    except ImportError:
        lib = False
    mode = "claude" if (key and lib) else "mock"
    return {"mode": mode, "has_key": key, "has_library": lib}


def _mode() -> str:
    return ai_status()["mode"]


def _record_dataset(finding: dict, explanation: str, mode: str) -> None:
    """
    Store every finding + its explanation in dataset.jsonl.
    This is the heart of the hybrid phase: we collect real data now to train
    our own model later.
    """
    try:
        entry = {
            "ts": datetime.datetime.now().isoformat(timespec="seconds"),
            "rule_id": finding.get("id"),
            "cwe": finding.get("cwe"),
            "severity": finding.get("severity"),
            "snippet": finding.get("snippet"),
            "explanation": explanation,
            "source_mode": mode,
            "label": finding.get("severity"),  # preliminary label (reviewed manually later)
        }
        with DATASET_FILE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass  # dataset logging must never break the scan


def dataset_stats() -> dict:
    """Reads dataset.jsonl and returns training-data stats (for the research angle)."""
    if not DATASET_FILE.exists():
        return {"total": 0, "by_severity": {}, "by_rule": {}, "by_mode": {}}
    total = 0
    by_sev, by_rule, by_mode = {}, {}, {}
    try:
        with DATASET_FILE.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                total += 1
                by_sev[e.get("severity")] = by_sev.get(e.get("severity"), 0) + 1
                by_rule[e.get("rule_id")] = by_rule.get(e.get("rule_id"), 0) + 1
                by_mode[e.get("source_mode")] = by_mode.get(e.get("source_mode"), 0) + 1
    except Exception:
        pass
    return {"total": total, "by_severity": by_sev, "by_rule": by_rule, "by_mode": by_mode}


def _mock_explain(finding: dict) -> str:
    sev = _SEVERITY_LABEL.get(finding["severity"], finding["severity"])
    return (
        f"This is a «{finding['title']}» vulnerability ({finding['cwe']}), severity {sev}. "
        f"{finding['description']} "
        f"Detected on line {finding['line']}: `{finding['snippet']}`. "
        f"Suggested fix: {finding['remediation']}"
    )


def _mock_summary(scan: dict) -> str:
    s = scan["summary"]
    return (
        f"Scanned {scan['lines_scanned']} lines of {scan['language']}. "
        f"Result: {scan['total_findings']} issue(s) "
        f"(critical: {s.get('critical',0)}, high: {s.get('high',0)}, "
        f"medium: {s.get('medium',0)}, low: {s.get('low',0)}). "
        f"Security score {scan['security_score']}/100. "
        + ("Start with the critical issues immediately." if s.get("critical") else
           "No critical issues — focus on high, then medium.")
    )


def _claude_analyze(scan: dict) -> dict:
    """Real analysis via the Claude API (used when a key is available)."""
    import anthropic
    client = anthropic.Anthropic()
    findings_text = json.dumps(scan["findings"], ensure_ascii=False, indent=2)
    prompt = (
        "You are a cybersecurity expert. Analyze the following scan findings. "
        "For each finding, write a simple explanation in English and estimate a "
        "confidence level (high/medium/low) to reduce false positives. Then write "
        "an executive summary. Return the result as JSON with keys: summary, "
        "findings (a list of objects with index, explanation, confidence).\n\n"
        f"Findings:\n{findings_text}"
    )
    msg = client.messages.create(
        model=os.getenv("ANTHROPIC_MODEL", "claude-opus-4-8"),
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}],
    )
    data = json.loads(msg.content[0].text)
    return data


def analyze(scan: dict) -> dict:
    """
    Adds the AI explanation to each finding + an executive summary.
    Works in all cases (even without a key) thanks to mock mode.
    """
    mode = _mode()

    if mode == "claude":
        try:
            ai = _claude_analyze(scan)
            scan["ai_summary"] = ai.get("summary", _mock_summary(scan))
            ai_map = {item["index"]: item for item in ai.get("findings", [])}
            for idx, f in enumerate(scan["findings"]):
                item = ai_map.get(idx, {})
                f["ai_explanation"] = item.get("explanation") or _mock_explain(f)
                f["ai_confidence"] = item.get("confidence", "medium")
                _record_dataset(f, f["ai_explanation"], mode)
            scan["ai_mode"] = "claude"
            return scan
        except Exception as e:
            scan["ai_error"] = f"Claude call failed, fell back to local mode: {e}"
            mode = "mock"

    # Local (mock) mode
    scan["ai_summary"] = _mock_summary(scan)
    for f in scan["findings"]:
        f["ai_explanation"] = _mock_explain(f)
        f["ai_confidence"] = "AI"
        _record_dataset(f, f["ai_explanation"], mode)
    scan["ai_mode"] = "mock"
    return scan
