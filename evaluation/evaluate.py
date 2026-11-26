"""
Evaluation harness — Cyber Shield AI
====================================
Measures the static scanner's accuracy against the labeled dataset
(evaluation/dataset.py) and writes a report (evaluation/REPORT.md).

Metrics (sample-level binary classification: vulnerable vs safe):
  TP = vulnerable sample correctly flagged
  FN = vulnerable sample missed
  TN = safe sample correctly left clean
  FP = safe sample wrongly flagged
  Precision = TP / (TP + FP)      (how trustworthy a "vulnerable" verdict is)
  Recall    = TP / (TP + FN)      (how many real vulnerabilities we catch)
  F1        = 2*P*R / (P + R)
  Accuracy  = (TP + TN) / total

Also reports per-CWE detection (did the right rule fire?) and lists the exact
false positives / false negatives for error analysis.

Run:  .venv\\Scripts\\python evaluation\\evaluate.py
"""

import sys
from pathlib import Path

# make "backend" importable when run from the project root
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.scanner import scan_code          # noqa: E402
from evaluation.dataset import SAMPLES          # noqa: E402


def evaluate():
    tp = fp = tn = fn = 0
    false_positives = []   # (id, detected rule ids)
    false_negatives = []   # (id, expected cwes)
    cwe_total = {}         # expected count per CWE
    cwe_hit = {}           # detected count per CWE
    rows = []

    for s in SAMPLES:
        result = scan_code(s["code"], filename=f"{s['id']}.{ 'js' if s['language']=='javascript' else 'py'}")
        detected_cwes = {f["cwe"] for f in result["findings"]}
        detected_rules = sorted({f["id"] for f in result["findings"]})
        flagged = len(result["findings"]) > 0

        # sample-level confusion
        if s["vulnerable"]:
            if flagged:
                tp += 1
            else:
                fn += 1
                false_negatives.append((s["id"], s["expected_cwes"]))
            # per-CWE recall
            for cwe in s["expected_cwes"]:
                cwe_total[cwe] = cwe_total.get(cwe, 0) + 1
                if cwe in detected_cwes:
                    cwe_hit[cwe] = cwe_hit.get(cwe, 0) + 1
        else:
            if flagged:
                fp += 1
                false_positives.append((s["id"], detected_rules))
            else:
                tn += 1

        rows.append({
            "id": s["id"], "vulnerable": s["vulnerable"],
            "flagged": flagged, "rules": detected_rules,
        })

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / total if total else 0.0

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "total": total,
        "precision": precision, "recall": recall, "f1": f1, "accuracy": accuracy,
        "false_positives": false_positives, "false_negatives": false_negatives,
        "cwe_total": cwe_total, "cwe_hit": cwe_hit, "rows": rows,
    }


def _pct(x):
    return f"{x*100:.1f}%"


def build_report(m) -> str:
    lines = []
    lines.append("# Cyber Shield AI — Scanner Evaluation Report\n")
    lines.append("Automated evaluation of the static code scanner against a labeled dataset.\n")
    lines.append(f"- Total samples: **{m['total']}** "
                 f"({m['tp']+m['fn']} vulnerable, {m['tn']+m['fp']} safe)\n")

    lines.append("## Confusion matrix (sample-level)\n")
    lines.append("| | Predicted vulnerable | Predicted safe |")
    lines.append("|---|---|---|")
    lines.append(f"| **Actually vulnerable** | TP = {m['tp']} | FN = {m['fn']} |")
    lines.append(f"| **Actually safe** | FP = {m['fp']} | TN = {m['tn']} |\n")

    lines.append("## Headline metrics\n")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Precision | **{_pct(m['precision'])}** |")
    lines.append(f"| Recall (detection rate) | **{_pct(m['recall'])}** |")
    lines.append(f"| F1-score | **{_pct(m['f1'])}** |")
    lines.append(f"| Accuracy | **{_pct(m['accuracy'])}** |\n")

    lines.append("## Per-CWE detection (recall by vulnerability type)\n")
    lines.append("| CWE | Detected / Expected | Rate |")
    lines.append("|---|---|---|")
    for cwe in sorted(m["cwe_total"]):
        hit = m["cwe_hit"].get(cwe, 0)
        tot = m["cwe_total"][cwe]
        lines.append(f"| {cwe} | {hit}/{tot} | {_pct(hit/tot)} |")
    lines.append("")

    lines.append("## Error analysis\n")
    lines.append(f"**False positives ({len(m['false_positives'])})** — safe code wrongly flagged:\n")
    if m["false_positives"]:
        for sid, rules in m["false_positives"]:
            lines.append(f"- `{sid}` → triggered {', '.join(rules)}")
    else:
        lines.append("- none")
    lines.append(f"\n**False negatives ({len(m['false_negatives'])})** — real vulnerabilities missed:\n")
    if m["false_negatives"]:
        for sid, cwes in m["false_negatives"]:
            lines.append(f"- `{sid}` → missed {', '.join(cwes)}")
    else:
        lines.append("- none")

    lines.append("\n## Interpretation\n")
    lines.append(
        "The scanner favours **recall over precision**: it catches most real "
        "vulnerabilities but also over-flags some safe patterns (e.g. `%s` query "
        "placeholders, `subprocess.run` with a safe argument list). This is exactly "
        "the gap the **AI layer** is meant to close — by reviewing each raw finding "
        "and filtering false positives. Measuring that improvement (precision with "
        "the Claude-API filter enabled vs. the raw scanner) is the next experiment, "
        "and requires `ANTHROPIC_API_KEY` to be set.\n"
    )
    lines.append("## Reproduce\n")
    lines.append("```\n.venv\\Scripts\\python evaluation\\evaluate.py\n```")
    return "\n".join(lines) + "\n"


def main():
    m = evaluate()
    report = build_report(m)
    out = Path(__file__).parent / "REPORT.md"
    out.write_text(report, encoding="utf-8")

    # console summary
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    print(f"Samples: {m['total']}  |  TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']}")
    print(f"Precision={_pct(m['precision'])}  Recall={_pct(m['recall'])}  "
          f"F1={_pct(m['f1'])}  Accuracy={_pct(m['accuracy'])}")
    print(f"Report written to: {out}")


if __name__ == "__main__":
    main()
