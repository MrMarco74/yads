"""Beta / opt-in module gating (#100): a module marked beta=True is hidden
from the scan-type UI by default and only appears for a tenant that has
explicitly opted in (via TenantModuleConfig.enabled=True for that module).
Non-beta modules keep their existing always-shown-unless-disabled behavior."""

from yads.core.module_registry import ModuleDef, get_scan_categories


def _names(categories):
    return {m.name for cat in categories for m in cat["modules"]}


def test_beta_module_hidden_by_default(monkeypatch):
    from yads.core import module_registry as reg
    # Inject a throwaway beta module into a real category.
    beta = ModuleDef(name="__beta_test_mod", label="Beta Test", label_de="Beta Test",
                     category="recon", module_path="", beta=True)
    monkeypatch.setitem(reg.REGISTRY, "__beta_test_mod", beta)

    # Not opted in -> hidden even though it's a normal recon module otherwise.
    assert "__beta_test_mod" not in _names(get_scan_categories())


def test_beta_module_shown_when_opted_in(monkeypatch):
    from yads.core import module_registry as reg
    beta = ModuleDef(name="__beta_test_mod2", label="Beta Test 2", label_de="Beta Test 2",
                     category="recon", module_path="", beta=True)
    monkeypatch.setitem(reg.REGISTRY, "__beta_test_mod2", beta)

    cats = get_scan_categories(beta_opted_in={"__beta_test_mod2"})
    assert "__beta_test_mod2" in _names(cats)


def test_non_beta_module_unaffected_by_beta_opt_in():
    # A normal module (dns_scanner is custom_dispatch; web_analyzer is shown)
    # is present regardless of beta_opted_in.
    assert "web_analyzer" in _names(get_scan_categories())
    assert "web_analyzer" in _names(get_scan_categories(beta_opted_in=set()))


def test_moduledef_beta_defaults_false():
    m = ModuleDef(name="x", label="x", label_de="x", category="recon")
    assert m.beta is False
