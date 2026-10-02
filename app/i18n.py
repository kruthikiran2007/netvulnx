"""Minimal internationalization (Milestone 21).

No new dependencies: UI strings are marked in templates with
``{{ _('...') }}`` and looked up in JSON catalogs under
``app/translations/<lang>.json``. The user's choice lives in the Flask
session (``session["lang"]``); anything untranslated falls back to the
English source string — the app never shows a blank label.

Adding a language:
  1. Copy ``app/translations/en.json`` to ``<lang>.json``.
  2. Translate the values (keys stay exactly as-is).
  3. Add the language to ``LANGUAGES`` below.
"""
import json
import os

from flask import session, request

LANGUAGES = {
    "en": "English",
    "hi": "हिन्दी",
}

_default = os.path.dirname(__file__)
_catalogs = {}


def _load(lang):
    if lang not in _catalogs:
        path = os.path.join(_default, "translations", f"{lang}.json")
        try:
            with open(path, encoding="utf-8") as fh:
                _catalogs[lang] = json.load(fh)
        except (OSError, ValueError):
            _catalogs[lang] = {}
    return _catalogs[lang]


def get_lang():
    """Current language: session choice, else the browser's preference,
    else English. Always a code we actually have."""
    lang = session.get("lang")
    if lang in LANGUAGES:
        return lang
    best = request.accept_languages.best_match(LANGUAGES)
    return best or "en"


def translate(text):
    """The ``_()`` used in templates."""
    lang = get_lang()
    if lang == "en":
        return text
    return _load(lang).get(text, text)


def set_lang(lang):
    if lang in LANGUAGES:
        session["lang"] = lang
        return True
    return False


def init_app(app):
    @app.context_processor
    def _inject_i18n():
        return {"_": translate, "get_lang": get_lang,
                "languages": LANGUAGES}
