# Cyber Shield AI — Scanner Evaluation Report

Automated evaluation of the static code scanner against a labeled dataset.

- Total samples: **24** (12 vulnerable, 12 safe)

## Confusion matrix (sample-level)

| | Predicted vulnerable | Predicted safe |
|---|---|---|
| **Actually vulnerable** | TP = 12 | FN = 0 |
| **Actually safe** | FP = 2 | TN = 10 |

## Headline metrics

| Metric | Value |
|---|---|
| Precision | **85.7%** |
| Recall (detection rate) | **100.0%** |
| F1-score | **92.3%** |
| Accuracy | **91.7%** |

## Per-CWE detection (recall by vulnerability type)

| CWE | Detected / Expected | Rate |
|---|---|---|
| CWE-295 | 1/1 | 100.0% |
| CWE-327 | 1/1 | 100.0% |
| CWE-338 | 1/1 | 100.0% |
| CWE-489 | 1/1 | 100.0% |
| CWE-502 | 1/1 | 100.0% |
| CWE-78 | 1/1 | 100.0% |
| CWE-79 | 1/1 | 100.0% |
| CWE-798 | 2/2 | 100.0% |
| CWE-89 | 2/2 | 100.0% |
| CWE-95 | 1/1 | 100.0% |

## Error analysis

**False positives (2)** — safe code wrongly flagged:

- `safe_subprocess_list` → triggered CMDI-001
- `safe_sql_param_percent` → triggered SQLI-001

**False negatives (0)** — real vulnerabilities missed:

- none

## Interpretation

The scanner favours **recall over precision**: it catches most real vulnerabilities but also over-flags some safe patterns (e.g. `%s` query placeholders, `subprocess.run` with a safe argument list). This is exactly the gap the **AI layer** is meant to close — by reviewing each raw finding and filtering false positives. Measuring that improvement (precision with the Claude-API filter enabled vs. the raw scanner) is the next experiment, and requires `ANTHROPIC_API_KEY` to be set.

## Reproduce

```
.venv\Scripts\python evaluation\evaluate.py
```
