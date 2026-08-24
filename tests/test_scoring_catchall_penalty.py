from types import SimpleNamespace
from yads.core.scoring import calculate_target_score, SCORED_MODULE_NAMES


def _mod_result(data):
    return SimpleNamespace(data=data)


def test_catchall_detector_in_scored_module_names():
    assert "catchall_detector" in SCORED_MODULE_NAMES


def test_parked_domain_deducts_from_score():
    latest_results = {
        "catchall_detector": _mod_result({
            "is_catch_all": True,
            "findings": [{"severity": "high", "title": "Domain appears to be parked (sedo)"}],
        }),
    }
    score, grade, factors = calculate_target_score(target=None, latest_results=latest_results)
    assert score == 96  # 100 - min(20, 1*4)
    assert any("parked" in f.lower() for f in factors)


def test_not_parked_domain_no_deduction():
    latest_results = {
        "catchall_detector": _mod_result({"is_catch_all": False, "findings": []}),
    }
    score, grade, factors = calculate_target_score(target=None, latest_results=latest_results)
    assert score == 100
    assert not any("parked" in f.lower() for f in factors)


def test_missing_catchall_result_no_deduction():
    score, grade, factors = calculate_target_score(target=None, latest_results={})
    assert score == 100
