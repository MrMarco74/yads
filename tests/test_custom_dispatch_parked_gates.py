"""
Confirms the four custom-dispatch modules' worker_tasks.py source each
exclude parked domains from their effective run-condition. This is a
source-scan test (like tests/test_public_api_service_names.py) rather than
an execution test, since exercising the real run_all_scans function
requires a live DB/Celery context impractical to fully mock for four
separate blocks.

Two of the four gates (`nuclei_scanner`, `visual_osint`) keep a simple
single `if "<name>" in scan_types ...:` condition, so `not is_parked` is
expected directly on that line.

The other two (`crawler`, `content_discovery`) have an existing `elif
"<name>" in scan_types: ...` fallback branch used to log an accurate
"port closed" message. Naively appending `and not is_parked` only to the
first `if` would cause a parked domain with reachable HTTP to fall into
that fallback and wrongly log "port closed" instead of "domain is
parked". So for these two, the fix is expected to add a *dedicated*
`elif "<name>" in scan_types and is_parked:` branch (logging that the
domain is parked) ahead of the generic fallback. This test checks for
that expanded three-way shape rather than requiring `not is_parked` to
appear literally on the primary `if` line.
"""
import re
from pathlib import Path

YADS_ROOT = Path(__file__).resolve().parents[1] / "yads"

SIMPLE_GATED_MODULES = ["visual_osint", "nuclei_scanner"]
ELIF_GATED_MODULES = ["crawler", "content_discovery"]


def _read_src():
    return (YADS_ROOT / "worker_tasks.py").read_text()


def test_simple_gates_exclude_parked_domains():
    src = _read_src()
    for name in SIMPLE_GATED_MODULES:
        pattern = re.compile(rf'if\s+"{name}"\s+in\s+scan_types[^\n:]*:', re.MULTILINE)
        match = pattern.search(src)
        assert match, f"could not find dispatch gate for {name}"
        assert "not is_parked" in match.group(0), (
            f"{name}'s gate condition does not exclude parked domains: {match.group(0)!r}"
        )


def test_elif_gates_have_dedicated_parked_branch():
    src = _read_src()
    for name in ELIF_GATED_MODULES:
        # Find the primary `if "<name>" in scan_types ... :` line and the
        # block of `elif` lines that immediately follow it (before blank line).
        block_pattern = re.compile(
            rf'if\s+"{name}"\s+in\s+scan_types[^\n]*:\n'
            rf'(?:[^\n]*\n)*?'
            rf'(?P<elifs>(?:\s*elif\s+"{name}"\s+in\s+scan_types[^\n]*:\n[^\n]*\n)+)',
            re.MULTILINE,
        )
        match = block_pattern.search(src)
        assert match, f"could not find dispatch gate block for {name}"

        primary_if_line = re.search(
            rf'if\s+"{name}"\s+in\s+scan_types[^\n:]*:', src
        ).group(0)
        assert "not is_parked" in primary_if_line, (
            f"{name}'s primary gate condition does not exclude parked domains: "
            f"{primary_if_line!r}"
        )

        elifs_text = match.group("elifs")
        # There must be a dedicated elif branch keyed on is_parked, with its own
        # accurate log message (not the generic "port closed" message), placed
        # before the generic fallback elif.
        parked_elif = re.search(
            rf'elif\s+"{name}"\s+in\s+scan_types\s+and\s+is_parked\s*:\s*\n\s*[^\n]*',
            elifs_text,
        )
        assert parked_elif, (
            f"{name} is missing a dedicated 'elif ... and is_parked:' branch "
            f"to keep the port-closed log message accurate: {elifs_text!r}"
        )
        assert "parked" in parked_elif.group(0).lower(), (
            f"{name}'s parked elif branch doesn't log about the domain being parked: "
            f"{parked_elif.group(0)!r}"
        )

        # The generic fallback elif (no is_parked condition) must still exist,
        # for the case scan_types includes the module but port 80/443 is closed
        # and the domain isn't parked.
        generic_elif = re.search(
            rf'elif\s+"{name}"\s+in\s+scan_types\s*:\s*\n\s*[^\n]*',
            elifs_text,
        )
        assert generic_elif, (
            f"{name} is missing its original generic fallback elif branch: {elifs_text!r}"
        )
        assert "port" in generic_elif.group(0).lower(), (
            f"{name}'s generic fallback elif no longer logs the port-closed reason: "
            f"{generic_elif.group(0)!r}"
        )
