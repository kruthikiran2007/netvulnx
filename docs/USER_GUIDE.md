# NetVulnX User Guide

A plain-English walkthrough of the web app. You don't need to know how to
code — but you do need permission to scan whatever you point NetVulnX at.

## Starting the app

```bash
cd ~/workspace/netvulnx
source venv/bin/activate   # use the project's isolated Python environment
python run.py              # starts the app at http://127.0.0.1:5000
```

Open `http://127.0.0.1:5000` in your browser. Nothing scans until you tell
it to.

## Running your first scan

1. Click **+ New scan**.
2. **Target:** an IP, hostname, or CIDR you own or may test — e.g.
   `127.0.0.1` (your own machine). Public internet addresses are rejected
   by default.
3. **Profile:** Quick (common ports), Standard, Deep (all 65k — slow), or
   Custom (your own port list).
4. Click through to the **authorization page**. Read it: it shows exactly
   which hosts and ports will be touched and a worst-case time estimate.
5. Tick the confirmation box and submit. The scan runs in the background;
   the detail page shows live progress. You can cancel any time.

## The pages

**Dashboard** — the big picture. Totals for scans, assets, open ports and
findings; findings broken down by severity; a bar chart of the risk score
of each completed scan; the 5 most recent findings with links.

**Assets** — every IP address ever seen, grouped across scans. One row per
IP: hostname, first/last seen, how many scans saw it, the union of open
ports observed, finding count, and worst severity. Click an IP for its
timeline: what each scan saw on that host, newest first.

**Attack surface** — what is reachable, aggregated across completed scans
only (a cancelled scan's half-finished data would be misleading):

- how many assets have open ports, how many distinct services are exposed,
  total findings;
- a chart + table of exposures per service (most exposed first);
- a chart of findings by severity;
- the latest completed scan's per-asset port map — each port chip coloured
  by the worst finding on that port (grey = no finding).

**Scans** — every scan with its status and risk score. Click through for
the full detail: assets, open ports and services, service analysis
(TLS/HTTP/DNS/SMTP/FTP observations), and findings.

## Reading findings

Each finding card shows:

- **Severity** (critical/high/medium/low/info) — how bad it is *if abused*.
- **Confidence** (confirmed/likely/potential/informational) — how sure the
  measurement is. Severity and confidence are independent: a "potential
  critical" is worth checking but not proven.
- **Evidence** — the exact measured facts that triggered the rule.
- **Impact / Remediation** — why it matters and how to fix it, with
  reference links.

The **risk score** on a scan is `10 × critical + 5 × high + 3 × medium +
1 × low` (informational = 0). It measures how much the rules matched, not
how "hacked" you are. **A score of 0 means no rule matched — not that the
target is secure.**

An open port with no finding is not a vulnerability: it is just a reachable
service. NetVulnX never invents findings.

## Honest limitations

- Only TCP connect scans — no UDP, no OS detection, no vulnerability
  database (CVE) lookups yet.
- "Secure" is never claimed; absence of findings ≠ absence of problems.
- Charts need internet once (Chart.js CDN); the tables beside them always
  work offline.
