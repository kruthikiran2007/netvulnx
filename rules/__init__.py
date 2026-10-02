"""The rule engine: deterministic detection, no invented findings.

How it works:
  1. The scan engine builds a *context* dict per open port: the Port row plus
     its TlsInfo / HttpInfo / ServiceCheck observations (all measured facts).
  2. `evaluate(ctx)` runs every registered rule's `match(ctx)`.
  3. A rule returns an *evidence* dict (measured values) when its condition
     holds, or None when it doesn't. No match -> no finding. Ever.

Rule schema (see docs/RULE_DEVELOPMENT.md for the full authoring guide):
    id          stable slug, e.g. "tls-cert-expired"
    title       short human title
    severity    critical | high | medium | low | info
    confidence  confirmed | likely | potential | informational
    description what was found, in plain language
    impact      why it matters
    remediation what to do about it
    references  list of real documentation URLs
    match       fn(ctx) -> evidence dict | None

Severity is about *impact if abused*; confidence is about *how sure the
measurement is*. A finding can be high-severity but only "likely", or
low-severity and "confirmed" — the two axes are independent, on purpose.
"""
from rules import tls_rules, http_rules, service_rules, cve_rules, ssh_rules, udp_rules

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}

CONFIDENCES = ("confirmed", "likely", "potential", "informational")

ALL_RULES = (tls_rules.RULES + http_rules.RULES + service_rules.RULES +
             cve_rules.RULES + ssh_rules.RULES + udp_rules.RULES)

# Guardrail: rule IDs must be unique and the schema must be complete.
# A broken rule definition fails fast at import, not mid-scan.
_ids = [r["id"] for r in ALL_RULES]
assert len(_ids) == len(set(_ids)), f"duplicate rule ids: {_ids}"
for _r in ALL_RULES:
    for _key in ("id", "title", "severity", "confidence", "description",
                 "impact", "remediation", "references", "match"):
        assert _key in _r, f"rule {_r.get('id')} missing key: {_key}"
    assert _r["severity"] in SEVERITIES, f"rule {_r['id']}: bad severity"
    assert _r["confidence"] in CONFIDENCES, f"rule {_r['id']}: bad confidence"
    assert callable(_r["match"]), f"rule {_r['id']}: match not callable"


def evaluate(ctx: dict) -> list:
    """Run all rules against one port's context.

    Returns [(rule, evidence), ...] for the rules that matched.
    A rule that raises is skipped — a buggy rule must never crash a scan.
    (Rules are unit-tested individually; see tests/test_rules.py.)
    """
    matched = []
    for rule in ALL_RULES:
        try:
            evidence = rule["match"](ctx)
        except Exception:
            continue
        if evidence:
            matched.append((rule, evidence))
    return matched
