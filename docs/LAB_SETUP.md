# LAB_SETUP.md — Building a Safe Test Lab

You need targets you are **allowed** to scan. This guide gives you three
tiers, from zero-setup to realistic.

## Ground rules

- NetVulnX's default config only allows loopback and private ranges
  (`127/8`, `10/8`, `172.16/12`, `192.168/16`). This guide stays inside
  those ranges — never "try it on" a public site.
- The fake services below are **intentionally vulnerable-looking** (old
  TLS, missing headers). That's the point: a lab where findings are
  guaranteed, so you can learn triage and reporting safely.

## Tier 0 — Nothing to install (2 minutes)

The end-to-end test suite already spins up fake services on
`127.0.0.1`:

```bash
cd ~/workspace/netvulnx
source venv/bin/activate
python -m pytest tests/ -q
```

For a *visible* lab, run the app and scan `127.0.0.1` while something
listens — e.g. Python's own HTTP server in another terminal:

```bash
python3 -m http.server 8000 --bind 127.0.0.1
```

Then in NetVulnX: New Scan → target `127.0.0.1` → Custom → ports `8000`.
You'll get an informational finding set (open HTTP, no TLS, headers —
great for learning what "informational" means).

## Tier 1 — Fake vulnerable services (recommended for the demo)

The verification scripts in `/tmp/verify_m5.py` / `/tmp/verify_m6.py`
contain small fake HTTPS/HTTP/FTP/SMTP servers with deliberate
misconfigurations (weak TLS, verbose banners). They bind to high
loopback ports (e.g. `127.0.0.1:8443`-style ports) and only accept local
connections.

To reuse one for a live demo:

1. Open the script, find the fake-service section, and run just the
   servers (or ask your assistant to extract them into
   `lab/fake_services.py`).
2. Start NetVulnX (`python run.py`).
3. New Scan → target `127.0.0.1` → Custom → the fake ports.
4. Authorize, watch live progress, then triage findings and print the
   HTML report.

Expected: a mix of medium/low TLS and HTTP findings — perfect for
showing the full workflow: scan → findings → triage → report → compare
(two runs, fix nothing, show drift = 0; or stop one service and show
"2 ports closed").

## Tier 2 — Virtual machines (most realistic)

For a real network with real operating systems:

1. Install VirtualBox/VMware/KVM.
2. Create a **host-only network** (e.g. `192.168.56.0/24`) — VMs can talk
   to your machine but not to the internet or your LAN.
3. Add a deliberately vulnerable VM:
   - **Metasploitable 2/3** (classic intentionally-vulnerable Linux),
   - or an old Linux ISO with default services enabled.
4. Snapshot the VM **before** scanning so you can reset.
5. In NetVulnX, scan the VM's host-only IP (e.g. `192.168.56.101`).

⚠️ Only download VM images from their official sources, keep them on the
host-only network, and never bridge a vulnerable VM to the internet or
your home LAN.

## Tier 3 — Containers (lightweight alternative)

```bash
docker network create --subnet=172.20.0.0/16 netvulnx-lab
docker run -d --name web --network netvulnx-lab nginx:1.14   # old, chatty
docker run -d --name ftp --network netvulnx-lab -p 127.0.0.1:2121:21 \
  stilliard/pure-ftpd:hardened
```

Find container IPs with `docker inspect` and scan them (they're in
`172.16/12`, allowed by default). Old image tags give you real
version-disclosure findings.

## Checklist before any scan

- [ ] I own the target, or have written permission.
- [ ] The target is on loopback / private / host-only — no public IPs.
- [ ] I can reset the target (snapshot / container recreate).
- [ ] I clicked **Authorize** myself — no scan runs without it.
