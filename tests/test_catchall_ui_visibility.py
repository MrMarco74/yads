"""
catchall_detector is default_on=False but "stays opt-in for UI display" — it
must remain selectable in the scan-type UI. Promoting it to custom_dispatch
(f28b85e8) dropped it out of get_scan_categories()'s UI_MODULES allowlist
(which only auto-includes non-custom_dispatch modules), silently removing the
"Catch-All Page Detector" checkbox from the bulk-scan and target-detail scan
pickers. This pins it back.
"""


def _all_module_names(categories):
    return {m.name for cat in categories for m in cat["modules"]}


def test_catchall_detector_is_shown_in_scan_type_ui():
    from yads.core.module_registry import get_scan_categories
    names = _all_module_names(get_scan_categories())
    assert "catchall_detector" in names


def test_catchall_detector_shown_even_though_custom_dispatch():
    """Guard the specific cause: it is custom_dispatch yet must still render."""
    from yads.core.module_registry import REGISTRY, get_scan_categories
    assert REGISTRY["catchall_detector"].custom_dispatch is True
    names = _all_module_names(get_scan_categories())
    assert "catchall_detector" in names
