"""Risk scoring: a deliberately simple, fully explainable formula.

Score = sum of severity weights across all findings in a scan.

    critical  10
    high       5
    medium     3
    low        1
    info       0

This is a *triage aid*, not a security rating. A score of 0 does not mean
"secure" — it means none of our rules matched. The number exists so you can
compare scans and see at a glance where the heavy findings are; the real
information is in the findings themselves. The formula is shown in the UI
next to every score so nobody mistakes it for something cleverer.
"""

SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 5,
    "medium": 3,
    "low": 1,
    "info": 0,
}

FORMULA_TEXT = ("Risk score = 10 x critical + 5 x high + 3 x medium + "
                "1 x low. Informational findings add 0.")


def score_findings(findings) -> int:
    """Sum severity weights for an iterable of Finding rows (or dicts)."""
    total = 0
    for f in findings:
        sev = f.severity if hasattr(f, "severity") else f.get("severity")
        total += SEVERITY_WEIGHTS.get(sev, 0)
    return total
