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

    # --- Reachability check settings (Milestone 1 scan) ---
    CONNECT_TIMEOUT = 2.0    # seconds to wait for a single TCP connection
    MAX_PORTS_PER_SCAN = 32  # sanity limit to keep checks quick and gentle
    DEFAULT_PORTS = "80,443,22"
