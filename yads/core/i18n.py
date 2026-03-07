"""
YADS Internationalization (i18n) — EN/DE support.

Usage in templates:  {{ _('nav.dashboard') }}
Usage in Python:     from yads.core.i18n import t; t('nav.dashboard', lang='de')

Language is set per-request via the yads_lang cookie and stored on User.language.
"""
import json
import os
from contextvars import ContextVar
from functools import lru_cache
from typing import Optional

# Per-request language (set by middleware from cookie)
_current_lang: ContextVar[str] = ContextVar("current_lang", default="en")

SUPPORTED_LANGS = {"en", "de"}
DEFAULT_LANG = "en"
_LOCALES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "locales")


@lru_cache(maxsize=None)
def _load_translations(lang: str) -> dict:
    path = os.path.join(_LOCALES_DIR, f"{lang}.json")
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def _get(translations: dict, key: str) -> Optional[str]:
    """Dot-notation lookup: 'nav.dashboard' → translations['nav']['dashboard']"""
    parts = key.split(".")
    node = translations
    for part in parts:
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node if isinstance(node, str) else None


def t(key: str, lang: Optional[str] = None) -> str:
    """Translate key to given language (or current request language)."""
    lang = lang if lang in SUPPORTED_LANGS else _current_lang.get()
    result = _get(_load_translations(lang), key)
    if result is None and lang != DEFAULT_LANG:
        result = _get(_load_translations(DEFAULT_LANG), key)
    return result if result is not None else key


def set_lang(lang: str) -> None:
    """Set language for current request context."""
    _current_lang.set(lang if lang in SUPPORTED_LANGS else DEFAULT_LANG)


def get_lang() -> str:
    """Get language for current request context."""
    return _current_lang.get()


def normalize_lang(lang: Optional[str]) -> str:
    """Return lang if supported, else DEFAULT_LANG."""
    return lang if lang in SUPPORTED_LANGS else DEFAULT_LANG
