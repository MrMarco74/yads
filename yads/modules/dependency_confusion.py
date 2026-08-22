"""
Dependency Confusion Check (#19)

Detects potential dependency confusion / namespace confusion attacks:
  - Crawls target for package.json, requirements.txt, Gemfile, pom.xml, go.mod
  - Extracts internal/private package names
  - Checks if those names are claimable on public registries (npm, PyPI, RubyGems)
  - Checks for package names on public registries that shouldn't be there
  - Identifies private registry configs (npmrc, pip.conf)

Dependency Confusion: attacker publishes malicious package with same name as
internal package — package managers may pull the public version instead.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin

import requests

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

TIMEOUT = 10
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; YADS-Security-Scanner/1.0)"}

# Files that reveal dependencies
DEPENDENCY_FILES = [
    "/package.json",
    "/package-lock.json",
    "/yarn.lock",
    "/requirements.txt",
    "/Pipfile",
    "/setup.py",
    "/setup.cfg",
    "/pyproject.toml",
    "/Gemfile",
    "/pom.xml",
    "/build.gradle",
    "/go.mod",
    "/composer.json",
    "/Cargo.toml",
    "/.npmrc",
    "/pip.conf",
]

# Patterns suggesting private/internal packages
PRIVATE_PATTERNS = re.compile(
    r"(@[a-z][a-z0-9_-]*\/[a-z][a-z0-9_-]*)",  # npm scoped packages
    re.IGNORECASE,
)

NPM_REGISTRY = "https://registry.npmjs.org/{package}"
PYPI_REGISTRY = "https://pypi.org/pypi/{package}/json"
RUBYGEMS_REGISTRY = "https://rubygems.org/api/v1/gems/{gem}.json"


def _clean_base(target: str) -> str:
    t = target.lower().strip()
    if not t.startswith("http"):
        t = "https://" + t
    return t.rstrip("/")


def _fetch(url: str) -> Optional[str]:
    try:
        r = requests.get(url, timeout=TIMEOUT, headers=HEADERS, verify=False, allow_redirects=True)
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return None


def _parse_npm_packages(content: str) -> List[str]:
    """Extract package names from package.json."""
    import json
    try:
        data = json.loads(content)
        packages = []
        for section in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
            packages.extend(data.get(section, {}).keys())
        return packages
    except Exception:
        return []


def _parse_python_packages(content: str) -> List[str]:
    """Extract package names from requirements.txt."""
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("-"):
            # Strip version specifiers
            name = re.split(r"[>=<!;\[\s]", line)[0].strip()
            if name:
                packages.append(name)
    return packages


def _parse_pyproject_packages(content: str) -> List[str]:
    """Extract from pyproject.toml dependencies."""
    packages = []
    in_deps = False
    for line in content.splitlines():
        line = line.strip()
        if "[tool.poetry.dependencies]" in line or "[project]" in line:
            in_deps = True
        elif line.startswith("[") and in_deps:
            in_deps = False
        if in_deps and "=" in line:
            name = line.split("=")[0].strip().strip('"').strip("'")
            if name and not name.startswith("#"):
                packages.append(name)
    return packages


def _parse_gemfile(content: str) -> List[str]:
    """Extract gem names from Gemfile."""
    packages = []
    for line in content.splitlines():
        m = re.match(r"""gem\s+['"]([^'"]+)['"]""", line.strip())
        if m:
            packages.append(m.group(1))
    return packages


def _parse_go_mod(content: str) -> List[str]:
    """Extract module paths from go.mod."""
    packages = []
    in_require = False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
        elif line == ")" and in_require:
            in_require = False
        elif in_require or line.startswith("require "):
            parts = line.replace("require ", "").split()
            if parts:
                packages.append(parts[0])
    return packages


def _check_npm_exists(package: str) -> bool:
    try:
        r = requests.get(
            NPM_REGISTRY.format(package=package),
            timeout=TIMEOUT,
        )
        return r.status_code == 200
    except Exception:
        return False


def _check_pypi_exists(package: str) -> bool:
    try:
        r = requests.get(
            PYPI_REGISTRY.format(package=package.lower().replace("-", "_")),
            timeout=TIMEOUT,
        )
        return r.status_code == 200
    except Exception:
        return False


def _check_rubygems_exists(gem: str) -> bool:
    try:
        r = requests.get(
            RUBYGEMS_REGISTRY.format(gem=gem),
            timeout=TIMEOUT,
        )
        return r.status_code == 200
    except Exception:
        return False


def _looks_internal(name: str) -> bool:
    """Heuristic: name looks like an internal/private package."""
    name_lower = name.lower()
    # Scoped npm packages (e.g. @company/pkg)
    if name.startswith("@") and "/" in name:
        return True
    # Common internal naming patterns
    internal_keywords = ["internal", "private", "corp", "company", "enterprise",
                         "local", "custom", "proprietary"]
    if any(k in name_lower for k in internal_keywords):
        return True
    # Very short names that look like internal shorthand
    if len(name) <= 3 and name.isalpha():
        return True
    return False


class DependencyConfusionScanner(BaseScannerModule):
    """Dependency confusion / namespace confusion attack surface check."""

    @property
    def module_name(self) -> str:
        return "dependency_confusion"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        base = _clean_base(target)
        domain = base.replace("https://", "").replace("http://", "")

        result: Dict[str, Any] = {
            "domain": domain,
            "files_found": [],
            "packages": {
                "npm": [],
                "python": [],
                "ruby": [],
                "go": [],
                "other": [],
            },
            "private_registry_configs": [],
            "vulnerable_packages": [],
            "findings": [],
            "summary": {
                "score": 100,
                "files_exposed": 0,
                "vulnerable_count": 0,
                "risk_level": "unknown",
            },
        }

        findings: List[Dict] = []
        npm_packages: List[str] = []
        python_packages: List[str] = []
        ruby_packages: List[str] = []
        go_packages: List[str] = []
        exposed_files: List[str] = []
        private_configs: List[str] = []

        for path in DEPENDENCY_FILES:
            url = urljoin(base + "/", path.lstrip("/"))
            content = _fetch(url)
            if content is None:
                continue

            exposed_files.append(path)

            if path == "/package.json":
                npm_packages.extend(_parse_npm_packages(content))
            elif path in ("/requirements.txt", "/Pipfile"):
                python_packages.extend(_parse_python_packages(content))
            elif path == "/pyproject.toml":
                python_packages.extend(_parse_pyproject_packages(content))
            elif path == "/Gemfile":
                ruby_packages.extend(_parse_gemfile(content))
            elif path == "/go.mod":
                go_packages.extend(_parse_go_mod(content))
            elif path in ("/.npmrc", "/pip.conf"):
                private_configs.append(path)
                # Check for registry URLs
                registry_urls = re.findall(r"https?://[^\s'\"]+", content)
                for url_str in registry_urls[:5]:
                    if "registry" in url_str.lower() or "pypi" not in url_str.lower():
                        private_configs.append(f"  → registry: {url_str[:80]}")

        result["files_found"] = exposed_files
        result["packages"]["npm"] = list(set(npm_packages))
        result["packages"]["python"] = list(set(python_packages))
        result["packages"]["ruby"] = list(set(ruby_packages))
        result["packages"]["go"] = list(set(go_packages))
        result["private_registry_configs"] = private_configs
        result["summary"]["files_exposed"] = len(exposed_files)

        # Continuous monitoring (#31): pull in scoped package names discovered
        # by js_secrets_scanner's JS-bundle analysis (require()/import), and
        # accumulate the candidate set across scans via baseline_diff rather
        # than resetting to only-what-this-scan-found each time — an internal
        # package name seen once in a JS bundle stays monitored even if a
        # later crawl doesn't happen to re-fetch that particular bundle.
        js_discovered: List[str] = []
        if target_id and self.db:
            try:
                from yads.models import ScanResult
                latest_js = (
                    self.db.query(ScanResult)
                    .filter(ScanResult.target_id == target_id, ScanResult.module_name == "js_secrets")
                    .order_by(ScanResult.scanned_at.desc())
                    .first()
                )
                if latest_js and latest_js.data:
                    js_discovered = latest_js.data.get("discovered_packages") or []
            except Exception as e:
                logger.debug(f"[DepConfusion] js_secrets_scanner lookup failed: {e}")

        candidate_scoped = set(p for p in npm_packages if p.startswith("@")) | set(js_discovered)
        if target_id and candidate_scoped:
            try:
                from yads.database import engine as _engine
                from sqlmodel import Session as _Session
                from yads.core.baseline_diff import diff_against_last
                with _Session(_engine) as _db:
                    diff = diff_against_last(_db, "dependency_confusion_monitored_packages", candidate_scoped, target_id=target_id)
                # Union of everything ever seen (added + unchanged), not just this run's delta.
                candidate_scoped = set(diff["added"]) | set(diff["unchanged"])
            except Exception as e:
                logger.debug(f"[DepConfusion] Monitored-package accumulation failed: {e}")

        # Check npm scoped/internal packages against public registry
        vulnerable: List[Dict] = []
        scoped_npm = sorted(candidate_scoped)
        internal_npm = [p for p in npm_packages if _looks_internal(p) and not p.startswith("@")]

        # Check if scoped packages exist publicly (potential confusion if private scope)
        for pkg in scoped_npm[:10]:
            if _check_npm_exists(pkg):
                # Scoped package exists publicly — could be legit or confusion
                pass
            else:
                vulnerable.append({
                    "package": pkg,
                    "registry": "npm",
                    "reason": "Scoped package not found on npm — if internal, name is squattable",
                    "severity": "high",
                })

        # Check unscoped internal-looking npm packages
        for pkg in internal_npm[:10]:
            if not _check_npm_exists(pkg):
                vulnerable.append({
                    "package": pkg,
                    "registry": "npm",
                    "reason": "Package name available on public npm registry",
                    "severity": "high",
                })

        # Check internal-looking Python packages
        internal_python = [p for p in python_packages if _looks_internal(p)]
        for pkg in internal_python[:5]:
            if not _check_pypi_exists(pkg):
                vulnerable.append({
                    "package": pkg,
                    "registry": "pypi",
                    "reason": "Package name available on public PyPI",
                    "severity": "high",
                })

        result["vulnerable_packages"] = vulnerable
        result["summary"]["vulnerable_count"] = len(vulnerable)

        score = 100

        # --- Findings ---
        if exposed_files:
            dep_files = [f for f in exposed_files if f not in ("/.npmrc", "/pip.conf")]
            if dep_files:
                sev = "medium" if len(dep_files) > 2 else "low"
                findings.append({
                    "severity": sev,
                    "title": f"Dependency manifests publicly exposed: {', '.join(dep_files[:4])}",
                    "description": (
                        "Package manifest files are accessible from the web root. "
                        "These reveal technology stack, internal package names, and version details "
                        "that assist attackers in planning dependency confusion or supply chain attacks."
                    ),
                    "files": dep_files,
                })
                if sev == "medium":
                    score -= 15
                else:
                    score -= 5

        if private_configs:
            findings.append({
                "severity": "medium",
                "title": "Private registry configuration file(s) exposed",
                "description": (
                    "Registry config files (.npmrc, pip.conf) are publicly accessible. "
                    "These may reveal internal registry URLs, authentication tokens, or "
                    "private package registry endpoints."
                ),
                "files": [c for c in private_configs if c.startswith("/")],
            })
            score -= 20

        if vulnerable:
            findings.append({
                "severity": "high",
                "title": f"{len(vulnerable)} package name(s) potentially vulnerable to dependency confusion",
                "description": (
                    "Internal/private package names found in manifests are not registered on public package "
                    "registries. An attacker could register these names with higher version numbers and "
                    "package managers may pull the malicious public version instead of the internal one."
                ),
                "packages": [v["package"] for v in vulnerable],
                "details": vulnerable,
            })
            score -= 40

        all_pkg_count = sum(len(v) for v in result["packages"].values())
        if not exposed_files:
            findings.append({
                "severity": "info",
                "title": "No dependency manifest files found at common paths",
                "description": "Package manifests were not publicly accessible at standard web root paths.",
            })
            result["summary"]["risk_level"] = "low"
        elif not vulnerable:
            findings.append({
                "severity": "info",
                "title": f"{all_pkg_count} package(s) found — no obvious confusion vulnerabilities detected",
                "description": "Dependency files are exposed but no unregistered internal package names were identified.",
            })
            result["summary"]["risk_level"] = "low"
        else:
            result["summary"]["risk_level"] = "high"

        result["findings"] = findings
        result["summary"]["score"] = max(0, score)
        return result
