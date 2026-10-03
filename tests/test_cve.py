# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Tests for CVE mapping (Milestone 9).

Network is never touched: _fetch fakes stand in for the NVD API, and the
DB cache is exercised through a throwaway SQLite database.
"""
import json
import tempfile
from datetime import datetime, timezone, timedelta

import pytest

from scanner import cve as cve_lib
from app import create_app, db
from app.models import CveCache
from config import Config


FAKE_CVES = [
    {"id": "CVE-2021-41773", "description": "Path traversal in Apache",
     "cvss": 7.5, "vector": "CVSS:3.1/AV:N/...", "published": "2021-10-05",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"},
    {"id": "CVE-2021-42013", "description": "Bypass of 41773 fix",
     "cvss": 9.8, "vector": "CVSS:3.1/AV:N/...", "published": "2021-10-07",
     "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-42013"},
]


def _fake_fetch(cpe):
    assert cpe.startswith("cpe:2.3:a:apache:http_server:2.4.49:")
    return list(FAKE_CVES)


# --- CPE building --------------------------------------------------------

def test_build_cpe_known_products():
    assert cve_lib.build_cpe("Apache", "2.4.1") == \
        "cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*"
    assert cve_lib.build_cpe("OpenSSH", "8.9p1") == \
        "cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*"
    assert cve_lib.build_cpe("nginx", "1.18.0").startswith("cpe:2.3:a:nginx:")


def test_build_cpe_rejects_unknown_or_missing():
    assert cve_lib.build_cpe("SomethingWeird", "1.0") is None
    assert cve_lib.build_cpe("Apache", None) is None
    assert cve_lib.build_cpe(None, "1.0") is None
    assert cve_lib.build_cpe("Apache", "notaversion") is None


def test_clean_version():
    assert cve_lib.clean_version("8.9p1") == "8.9"
    assert cve_lib.clean_version("2.4.1") == "2.4.1"
    assert cve_lib.clean_version("1.18.0-ubuntu") == "1.18.0"
    assert cve_lib.clean_version("") is None


# --- CVSS mapping -----------------------------------------------------------

def test_cvss_to_severity():
    assert cve_lib.cvss_to_severity(10.0) == "critical"
    assert cve_lib.cvss_to_severity(9.0) == "critical"
    assert cve_lib.cvss_to_severity(8.9) == "high"
    assert cve_lib.cvss_to_severity(7.0) == "high"
    assert cve_lib.cvss_to_severity(6.9) == "medium"
    assert cve_lib.cvss_to_severity(4.0) == "medium"
    assert cve_lib.cvss_to_severity(3.9) == "low"
    assert cve_lib.cvss_to_severity(0.1) == "low"
    assert cve_lib.cvss_to_severity(0.0) == "info"
    assert cve_lib.cvss_to_severity(None) == "info"


def test_extract_score_prefers_v31():
    cve = {"metrics": {
        "cvssMetricV31": [{"cvssData": {"baseScore": 7.5,
                                        "vectorString": "CVSS:3.1/AV:N"}}],
        "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]}}
    assert cve_lib._extract_score(cve) == (7.5, "CVSS:3.1/AV:N")


def test_extract_score_missing():
    assert cve_lib._extract_score({"metrics": {}}) == (None, "")


# --- lookup behavior --------------------------------------------------------

def test_lookup_uses_fetch_and_returns_cves():
    cves = cve_lib.lookup_cves("Apache", "2.4.49", _fetch=_fake_fetch)
    assert [c["id"] for c in cves] == ["CVE-2021-41773", "CVE-2021-42013"]


def test_lookup_unknown_product_never_calls_fetch():
    def boom(cpe):
        raise AssertionError("network must not be touched")
    assert cve_lib.lookup_cves("Nope", "1.0", _fetch=boom) == []


def test_lookup_fetch_failure_returns_empty():
    def down(cpe):
        raise OSError("network down")
    assert cve_lib.lookup_cves("Apache", "2.4.49", _fetch=down) == []


def test_lookup_caches_in_db():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()

    class _TestConfig(Config):
        SQLALCHEMY_DATABASE_URI = "sqlite:///" + tmp.name

    app = create_app(_TestConfig)
    calls = []

    def counting_fetch(cpe):
        calls.append(cpe)
        return list(FAKE_CVES)

    with app.app_context():
        first = cve_lib.lookup_cves("Apache", "2.4.49", _fetch=counting_fetch)
        second = cve_lib.lookup_cves("Apache", "2.4.49", _fetch=counting_fetch)
        assert first == second == FAKE_CVES
        assert len(calls) == 1  # second call served from cache
        row = db.session.get(CveCache, cve_lib.build_cpe("Apache", "2.4.49"))
        assert row is not None
        assert json.loads(row.payload) == FAKE_CVES


def test_lookup_cache_expiry_refetches():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()

    class _TestConfig(Config):
        SQLALCHEMY_DATABASE_URI = "sqlite:///" + tmp.name

    app = create_app(_TestConfig)
    calls = []

    def counting_fetch(cpe):
        calls.append(cpe)
        return list(FAKE_CVES)

    with app.app_context():
        cve_lib.lookup_cves("Apache", "2.4.49", _fetch=counting_fetch)
        # age the cache entry past the TTL
        cpe = cve_lib.build_cpe("Apache", "2.4.49")
        row = db.session.get(CveCache, cpe)
        row.fetched_at = datetime.now(timezone.utc) - timedelta(days=8)
        db.session.commit()
        cve_lib.lookup_cves("Apache", "2.4.49", _fetch=counting_fetch)
        assert len(calls) == 2  # expired -> fetched again


# --- rule wiring ------------------------------------------------------------

def test_cve_rule_registered_and_sane():
    from rules import ALL_RULES
    rule = next(r for r in ALL_RULES if r["id"] == "cve-known-vulnerabilities")
    assert rule["confidence"] == "likely"


def test_cve_rule_no_match_without_product_version():
    from rules import cve_rules
    rule = cve_rules.RULES[0]

    class FakePort:
        product, version = None, None
    assert rule["match"]({"port": FakePort()}) is None

    class FakePort2:
        product, version = "SomethingWeird", "1.0"
    assert rule["match"]({"port": FakePort2()}) is None
