# Rule engine (arrives in Milestone 4)

NetVulnX's differentiator is its **custom vulnerability detection rule engine**:
instead of "port 22 is open → HIGH", each rule performs a real, safe,
non-destructive check and only creates a finding when a defined security
condition is actually met.

Planned layout:

```
rules/
    __init__.py        # rule discovery: finds every rule module automatically
    base.py            # the Rule class every check inherits from
    ftp/
        anonymous.py   # FTP_ANONYMOUS_LOGIN — actually attempts anonymous login
    ssh/
        ...
    http/
        headers.py     # missing security headers, server disclosure
    tls/
        versions.py    # obsolete TLS versions offered by the server
```

Each rule will expose:

- `id` — unique, e.g. `FTP_ANONYMOUS_LOGIN`
- `title`, `description`, `severity`
- `check(target, service_info)` — runs the safe test, returns evidence
- `remediation` — what to do about it
- `references` — links to advisories / documentation
- confidence logic — Confirmed / Likely / Potential / Informational

**Status: planned.** No rule code exists yet — and per project principles,
nothing here pretends otherwise.
