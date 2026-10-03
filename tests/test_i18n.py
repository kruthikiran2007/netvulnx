# Copyright (c) 2026 kruthikiran2007. Licensed under the MIT License.
"""Tests for i18n (Milestone 21): catalog lookup, fallback, switching."""
import json

import pytest

from app import create_app, db
from config import Config


@pytest.fixture()
def app():
    import tempfile, os
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    class TConfig(Config):
        SQLALCHEMY_DATABASE_URI = "sqlite:///" + path
        TESTING = True

    app = create_app(TConfig)
    yield app
    # Windows locks open SQLite files: release all pooled connections
    # before deleting, or unlink() raises PermissionError.
    with app.app_context():
        db.session.remove()
        db.engine.dispose()
    os.unlink(path)


def test_catalogs_cover_same_keys():
    en = json.load(open("app/translations/en.json", encoding="utf-8"))
    hi = json.load(open("app/translations/hi.json", encoding="utf-8"))
    assert set(en) == set(hi)
    assert all(isinstance(v, str) and v for v in hi.values())


def test_english_passthrough(app):
    with app.test_request_context("/"):
        from app import i18n as i18n_lib
        assert i18n_lib.translate("Dashboard") == "Dashboard"


def test_hindi_lookup(app):
    with app.test_request_context("/"):
        from flask import session
        from app import i18n as i18n_lib
        session["lang"] = "hi"
        assert i18n_lib.translate("Dashboard") == "डैशबोर्ड"
        assert i18n_lib.translate("Log in") == "लॉग इन"


def test_fallback_for_unknown_string(app):
    with app.test_request_context("/"):
        from flask import session
        from app import i18n as i18n_lib
        session["lang"] = "hi"
        # Never in any catalog -> the English source shows, never blank.
        assert i18n_lib.translate("Some brand-new label") == "Some brand-new label"


def test_browser_preference_respected(app):
    with app.test_request_context("/", headers={"Accept-Language": "hi"}):
        from app import i18n as i18n_lib
        assert i18n_lib.get_lang() == "hi"


def test_set_lang_rejects_unknown(app):
    with app.test_request_context("/"):
        from app import i18n as i18n_lib
        assert i18n_lib.set_lang("xx") is False
        assert i18n_lib.set_lang("hi") is True


def test_switcher_route(app):
    client = app.test_client()
    r = client.get("/lang/hi")
    assert r.status_code in (302, 303)
    # Language persists in the session and the nav shows it.
    r = client.get("/lang/hi", follow_redirects=True)
    assert "हिन्दी" in r.get_data(as_text=True)
