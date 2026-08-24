from yads.core.module_registry import REGISTRY, get_simple_dispatch_modules


def test_catchall_detector_is_custom_dispatch():
    defn = REGISTRY["catchall_detector"]
    assert defn.custom_dispatch is True


def test_catchall_detector_is_finding_module():
    defn = REGISTRY["catchall_detector"]
    assert defn.finding_module is True


def test_catchall_detector_stays_opt_in_by_default():
    defn = REGISTRY["catchall_detector"]
    assert defn.default_on is False


def test_catchall_detector_excluded_from_simple_dispatch():
    names = [m.name for m in get_simple_dispatch_modules()]
    assert "catchall_detector" not in names
