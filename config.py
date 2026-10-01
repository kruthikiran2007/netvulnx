"""NetVulnX configuration.

This file holds the application's settings in ONE place.
To change how the app behaves, edit values here — not the code.
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    # --- Database ---
    # SQLite stores the whole database in a single file on disk.
    # No database server to install or configure.
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(BASE_DIR, "netvulnx.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- Web sessions ---
    # Used by Flask to sign session cookies and protect forms.
    # In a real deployment, set the NETVULNX_SECRET_KEY environment variable.
    SECRET_KEY = os.environ.get("NETVULNX_SECRET_KEY", "dev-only-change-me")

    # --- Safety controls ---
    # By default only these targets may be scanned:
    #   127.0.0.1 / ::1            -> this machine
    #   10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 -> private LANs / lab networks
    # Public internet addresses are REJECTED unless this is set to True
    # (explicit opt-in for authorized enterprise assessments).
    ALLOW_PUBLIC_TARGETS = False

    # --- Reachability / host-discovery settings ---
    CONNECT_TIMEOUT = 2.0    # seconds to wait for a single TCP connection
    MAX_PORTS_PER_SCAN = 32  # (legacy; scanner.targets.MAX_PORTS_PER_SCAN now rules)
    DEFAULT_PORTS = "80,443,22"

    # --- Port scan settings (Milestone 2) ---
    SCAN_WORKERS = 32        # max parallel TCP connections per scan (bounded!)
    PORT_TIMEOUT = 1.0       # seconds to wait for one port probe
    DISCOVERY_TIMEOUT = 1.0  # per-port timeout during host discovery
    BANNER_TIMEOUT = 3.0     # seconds to wait for a service banner

    # --- Scan profiles: each has clearly defined behavior ---
    SCAN_PROFILES = {
        "quick": {
            "label": "Quick Assessment",
            "description": ("Fast first look: 20 commonly exposed ports, "
                            "host discovery first, banner grabbing on open ports."),
            "ports": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                      443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443],
            "discovery": True,
        },
        "standard": {
            "label": "Standard Assessment",
            "description": ("Broader discovery across ~120 common service ports, "
                            "host discovery first, banner grabbing on open ports."),
            "ports": [
                20, 21, 22, 23, 25, 37, 42, 43, 53, 67, 68, 69, 79, 80,
                88, 110, 111, 113, 119, 123, 135, 137, 138, 139, 143,
                161, 162, 179, 194, 389, 443, 445, 465, 512, 513, 514,
                515, 540, 548, 554, 587, 591, 631, 636, 990, 993, 995,
                1025, 1080, 1194, 1433, 1434, 1521, 1723, 1755, 1900,
                2000, 2049, 2082, 2083, 2100, 2181, 2222, 2301, 2381,
                2427, 2483, 2484, 2967, 3000, 3128, 3222, 3260, 3268,
                3306, 3389, 3478, 3690, 3702, 3724, 3800, 4000, 4001,
                4045, 4190, 4333, 4340, 4369, 4443, 4444, 4500, 4567,
                4662, 4672, 4711, 4730, 4786, 4848, 4899, 4900, 5000,
                5001, 5009, 5050, 5060, 5061, 5101, 5120, 5190, 5222,
                5269, 5308, 5357, 5432, 5445, 5498, 5555, 5631, 5666,
                5672, 5722, 5800, 5900, 5938, 5985, 5986, 6000, 6001,
                6112, 6129, 6346, 6379, 6389, 6443, 6502, 6514, 6543,
            ],
            "discovery": True,
        },
        "deep": {
            "label": "Deep Assessment",
            "description": ("Thorough: full TCP 1-1024 scan on EVERY host "
                            "(no discovery shortcut), banner grabbing on open ports. "
                            "Slower, but won't miss a host that hides from discovery."),
            "ports": list(range(1, 1025)),
            "discovery": False,
        },
        "custom": {
            "label": "Custom",
            "description": ("Your own port list (up to 1024 ports). The exact ports "
                            "you name are always checked — no discovery shortcut."),
            "ports": None,  # resolved from the user's port field
            "discovery": False,  # overridden in engine: custom never skips
        },
    }
