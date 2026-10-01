# Rule Development Guide

How to add a detection rule to NetVulnX. A rule is the **only** way a
finding comes into existence: no rule match → no finding, ever. This is
deliberate — it is what keeps the scanner honest.

## The big idea

The scanner measures things (open ports, TLS handshakes, HTTP headers).
Those measurements are **facts**, stored in `TlsInfo` / `HttpInfo` /
`ServiceCheck` rows. A rule is a small, pure function that looks at the
facts for one port and answers one question: *"does the bad condition hold?"*

- **Yes** → return an evidence dict (the measured values that prove it).
- **No** → return `None`. The engine creates nothing.

Rules never invent data, never guess, and never reach the network. If the
measurement isn't there, the rule stays silent.

## Anatomy of a rule

Rules live in `rules/`:

```
rules/
├── __init__.py        # registry + evaluate()
├── tls_rules.py       # rules over TlsInfo
├── http_rules.py      # rules over HttpInfo
├── service_rules.py   # rules over ServiceCheck
└── scoring.py         # risk-score formula (not rules)
```

Each rule is a dict with a `match` function:

```python
def _match_example(ctx):
    tls = ctx.get("tls")          # a TlsInfo row, or None
    if tls and tls.cert_expired:  # the bad condition, measured
        return {"subject": tls.cert_subject,   # evidence, not prose
                "not_after": str(tls.cert_not_after)}
    return None                   # no match → no finding

RULES = [
    {
        "id": "tls-cert-expired",        # stable slug, unique
        "title": "TLS certificate has expired",
        "severity": "high",              # critical | high | medium | low | info
        "confidence": "confirmed",       # confirmed | likely | potential | informational
        "description": "What was found, plainly.",
        "impact": "Why it matters to the asset owner.",
        "remediation": "Concrete steps to fix it.",
        "references": ["https://..."],   # real docs only
        "match": _match_example,
    },
]
```

The `ctx` dict the engine builds per port:

| key      | value |
|----------|-------|
| `target` | what the user typed as the scan target |
| `scan` / `asset` / `port` | the SQLAlchemy rows |
| `tls`    | the `TlsInfo` row, or `None` |
| `http`   | the `HttpInfo` row, or `None` |
| `checks` | dict of `check_type` → `ServiceCheck` row |

## Choosing severity and confidence

These are **independent axes** — don't conflate them:

- **Severity** = impact *if abused*. `critical` (remote code execution
  class), `high` (breaks trust/encryption), `medium` (real risk, context
  dependent), `low` (hardening), `info` (worth knowing, not a vuln).
- **Confidence** = how sure the *measurement* is. `confirmed` (we directly
  observed the condition, e.g. completed an old-TLS handshake), `likely`
  (strong evidence with some inference, e.g. a default page suggests an
  unhardened install), `potential` (version-based / heuristic — none of the
  v1 rules use this yet), `informational` (a fact, not a judgment).

An open port is **never** a finding by itself — there is no rule for it,
on purpose.

## Writing the match function

1. **Pull the observation, bail out if it's missing or errored.**
   Every rule must handle `None` gracefully:
   ```python
   tls = ctx.get("tls")
   if tls is None or tls.error:
       return None
   ```
2. **Test the bad condition against measured fields only.** No heuristics
   on banners, no version-to-CVE guessing (that's a future milestone with
   a real vulnerability database).
3. **Return evidence as a plain dict of values**, not formatted prose.
   The UI renders it as "measured facts". Good: `{"cipher": "RC4",
   "bits": 40}`. Bad: `{"note": "cipher seems weak"}`.
4. **Use the model's real attribute names.** Test doubles in unit tests
   must mirror `app/models.py` exactly — a rule touching a wrong attribute
   raises, `evaluate()` skips it, and the rule silently never fires. (This
   exact bug happened in M4: `row.detail` vs the real `details` column.
   The regression test `test_rules_against_real_model_attributes` runs
   every rule against real model instances to prevent recurrence.)

For `ServiceCheck` rows, prefer the **structured detail fields**
(`anonymous_allowed`, `version`, `starttls_advertised`) over
string-matching `summary` — summaries are human text and may change.

## The safety net

- `rules/__init__.py` validates every rule at import: unique IDs,
  complete schema, legal severity/confidence values. A malformed rule
  fails fast at startup, not mid-scan.
- `evaluate()` wraps each rule in try/except: **one broken rule can never
  crash a scan** — it's skipped. (Unit tests are how broken rules get
  caught instead; see below.)

## Testing your rule

Add cases to `tests/test_rules.py`:

```python
def test_my_rule():
    _fires("my-rule-id", _ctx(tls=_tls(bad_thing=True)))     # must fire
    _silent("my-rule-id", _ctx(tls=_tls(bad_thing=False)))   # must not
    _silent("my-rule-id", _ctx(tls=None))                    # missing data
    _silent("my-rule-id", _ctx(tls=_tls(error="boom")))      # errored data
```

Every rule needs at least: a positive case, a negative case, and a
missing/errored-data case. Then run:

```bash
source venv/bin/activate
python -m pytest tests/test_rules.py -q
```

## Risk scoring

`rules/scoring.py` holds the formula — a plain weighted sum, shown next to
every score in the UI:

```
critical × 10 + high × 5 + medium × 3 + low × 1 (+ info × 0)
```

It is a **triage aid**, not a security rating. A score of 0 means "no rule
matched", not "secure". Keep it explainable: if you change the weights,
update `FORMULA_TEXT` and the UI text that quotes it.

## Checklist before committing a rule

- [ ] `match` returns evidence dict or `None`; handles `None`/errored rows
- [ ] Evidence contains measured values, no prose guesses
- [ ] Severity reflects impact-if-abused; confidence reflects measurement
- [ ] References are real, reachable documentation URLs
- [ ] Unit tests: fires / silent / missing-data cases pass
- [ ] `test_rules_against_real_model_attributes` still passes (it runs
      your rule against real model instances automatically)
