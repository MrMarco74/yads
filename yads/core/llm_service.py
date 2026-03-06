"""
LLM Service — pluggable AI analysis for YADS reports.

Supported providers (configured via SystemConfig):
  LLM_PROVIDER : disabled | ollama | openai | anthropic | custom
  LLM_API_URL  : base URL for ollama / custom OpenAI-compatible endpoint
  LLM_API_KEY  : API key (openai / anthropic / custom)
  LLM_MODEL    : model name  (e.g. llama3.2, gpt-4o-mini, claude-haiku-4-5-20251001)
  LLM_TIMEOUT  : request timeout in seconds (default 60)
"""

import asyncio
import json
import logging
from typing import Any, Dict, Optional

import requests as _requests

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 120
_DEFAULT_MODELS = {
    "ollama":    "llama3.2",
    "openai":    "gpt-4o-mini",
    "anthropic": "claude-haiku-4-5-20251001",
    "custom":    "gpt-4o-mini",
}


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

def _build_prompt(data: Dict[str, Any]) -> str:
    vs   = data.get("vuln_stats", {})
    sds  = data.get("service_distribution_stats", {})
    total_svc = sum(sds.values()) or 1
    https_pct = round(100 * (sds.get("HTTPS Only", 0) + sds.get("Both", 0)) / total_svc)

    ssl_expired = sum(1 for s in data.get("ssl_timeline", []) if s.get("status") == "expired")
    ssl_warn    = sum(1 for s in data.get("ssl_timeline", []) if s.get("status") in ("critical", "warning"))

    risk_feed = data.get("risk_feed", [])
    top_risks = [
        f"[{i.get('severity')}] {i.get('type')}: {i.get('title')} (target: {i.get('target', i.get('target_id', ''))})"
        for i in risk_feed[:15]
    ]

    # Secrets: from dedicated secrets_leaks list + any in risk_feed typed "Secret Leak"
    secrets_count = len(data.get("secrets_leaks", [])) + sum(
        1 for i in risk_feed if "Secret" in str(i.get("type", ""))
    )

    top_tech  = sorted(data.get("tech_stack", {}).items(), key=lambda x: x[1], reverse=True)[:12]
    top_countries = sorted(data.get("countries", {}).items(), key=lambda x: x[1], reverse=True)[:5]

    # Total scanned targets: prefer tech_details (web-scanned) over cloud_details
    total_web_targets  = len(data.get("tech_details", []))
    total_infra_targets = len(data.get("cloud_details", []))
    total_targets = max(total_web_targets, total_infra_targets)

    # HTTP status breakdown from status_codes dict
    status_codes = data.get("status_codes", {})

    summary = {
        "scope": {
            "total_targets_scanned": total_targets,
            "web_analyzed_targets": total_web_targets,
            "cloud_providers": list(data.get("cloud_providers", {}).keys()),
            "server_locations": [c for c, _ in top_countries],
            "unique_technologies": len(data.get("tech_stack", {})),
            "top_technologies": [f"{t} ({n})" for t, n in top_tech],
        },
        "vulnerabilities": {
            "critical": vs.get("critical", 0),
            "high":     vs.get("high", 0),
            "medium":   vs.get("medium", 0),
            "low":      vs.get("low", 0),
            "total":    sum(vs.values()),
        },
        "security_posture": {
            "https_coverage_pct":      https_pct,
            "http_no_redirect_targets": status_codes.get("http_no_redirect", 0),
            "ssl_expired_certs":       ssl_expired,
            "ssl_expiring_soon_certs": ssl_warn,
            "reputation_issues":       len(data.get("reputation_issues", [])),
            "open_cloud_buckets":      len(data.get("open_buckets", [])),
            "secrets_leaked_targets":  secrets_count,
            "hijackable_broken_links": len(data.get("hijacking_items", [])),
        },
        "http_status_distribution": status_codes,
        "top_risks": top_risks,
        "blacklisted_ips": [
            "{target} ({ip}): {flags}".format(
                target=i.get("target", ""),
                ip=i.get("ip", ""),
                flags=", ".join(
                    x.get("message", x.get("source", str(x))) if isinstance(x, dict) else str(x)
                    for x in i.get("issues", [])
                )
            )
            for i in data.get("reputation_issues", [])[:20]
        ],
        "hijackable_domains": [
            f"{i.get('target_domain')}: {i.get('broken_link')}"
            for i in data.get("hijacking_items", [])[:10]
        ],
        "largest_attack_surfaces": [
            f"{a['target']}: {a['count']} subdomains"
            for a in data.get("attack_surface_stats", [])[:5]
        ],
    }

    return (
        "You are a senior cybersecurity analyst writing an executive report. "
        "Analyze the following aggregated infrastructure security data and provide a structured risk assessment.\n\n"
        f"DATA:\n{json.dumps(summary, indent=2)}\n\n"
        "Respond with a single valid JSON object in this exact format (no markdown, no code blocks):\n"
        "{\n"
        '  "risk_rating": "LOW|MEDIUM|HIGH|CRITICAL",\n'
        '  "risk_score": <integer 0-100>,\n'
        '  "executive_summary": "<3-5 sentences, non-technical, suitable for C-level executives>",\n'
        '  "key_findings": ["<finding 1>", "<finding 2>", "<finding 3>"],\n'
        '  "recommendations": ["<rec 1>", "<rec 2>", "<rec 3>"]\n'
        "}\n\n"
        "Scoring guide: 0=no risk, 25=low, 50=medium, 75=high, 100=critical. "
        "key_findings: most impactful security issues. "
        "recommendations: specific, actionable, prioritized by urgency."
    )


# ---------------------------------------------------------------------------
# Provider backends
# ---------------------------------------------------------------------------

def _call_ollama(base_url: str, model: str, prompt: str, timeout: int) -> str:
    resp = _requests.post(
        f"{base_url.rstrip('/')}/api/generate",
        json={"model": model, "prompt": prompt, "stream": False, "format": "json"},
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()["response"]


def _call_openai_compat(base_url: str, api_key: str, model: str, prompt: str, timeout: int) -> str:
    from urllib.parse import urlparse
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload: Dict[str, Any] = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
    }
    _json_supported = ("openai.com", "generativelanguage.googleapis.com", "azure.com")
    if not base_url or any(h in base_url for h in _json_supported):
        payload["response_format"] = {"type": "json_object"}

    # If the base URL already contains a path (e.g. /v1beta/openai for Gemini),
    # only append /chat/completions — not /v1/chat/completions to avoid doubling.
    parsed_path = urlparse(base_url).path.rstrip("/")
    if parsed_path and parsed_path != "":
        completions_url = f"{base_url.rstrip('/')}/chat/completions"
    else:
        completions_url = f"{base_url.rstrip('/')}/v1/chat/completions"

    resp = _requests.post(completions_url, headers=headers, json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


def _call_anthropic(api_key: str, model: str, prompt: str, timeout: int) -> str:
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    resp = _requests.post(
        "https://api.anthropic.com/v1/messages",
        headers=headers,
        json={"model": model, "max_tokens": 1024, "messages": [{"role": "user", "content": prompt}]},
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()["content"][0]["text"]


def _run_sync(provider, api_key, api_url, model, prompt, timeout) -> str:
    """Synchronous dispatch — runs in thread executor from async context."""
    if provider == "ollama":
        return _call_ollama(api_url or "http://ollama:11434", model, prompt, timeout)
    elif provider == "openai":
        return _call_openai_compat("https://api.openai.com", api_key, model, prompt, timeout)
    elif provider == "anthropic":
        return _call_anthropic(api_key, model, prompt, timeout)
    elif provider == "custom":
        return _call_openai_compat(api_url, api_key, model, prompt, timeout)
    raise ValueError(f"Unknown provider: {provider}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def get_report_analysis(
    data: Dict[str, Any],
    config: Dict[str, str],
) -> Optional[Dict[str, Any]]:
    """
    Generate an AI risk assessment for the given infrastructure data.

    config keys: LLM_PROVIDER, LLM_API_URL, LLM_API_KEY, LLM_MODEL, LLM_TIMEOUT

    Returns a dict with keys:
        risk_rating, risk_score, executive_summary, key_findings, recommendations
    or None if LLM is disabled / fails.
    """
    provider = (config.get("LLM_PROVIDER") or "disabled").strip().lower()
    if provider == "disabled" or not provider:
        return None

    api_key  = config.get("LLM_API_KEY", "")
    api_url  = config.get("LLM_API_URL", "")
    model    = config.get("LLM_MODEL", "") or _DEFAULT_MODELS.get(provider, "")
    timeout  = int(config.get("LLM_TIMEOUT", _DEFAULT_TIMEOUT))
    prompt   = _build_prompt(data)

    try:
        loop = asyncio.get_event_loop()
        raw = await loop.run_in_executor(
            None, _run_sync, provider, api_key, api_url, model, prompt, timeout
        )

        # Strip markdown code fences if model wrapped the JSON
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]

        result = json.loads(raw)

        # Validate minimum required keys
        for key in ("risk_rating", "risk_score", "executive_summary"):
            if key not in result:
                raise ValueError(f"Missing key in LLM response: {key}")

        result.setdefault("key_findings", [])
        result.setdefault("recommendations", [])
        logger.info(f"[LLM] Analysis complete. Rating: {result['risk_rating']} Score: {result['risk_score']}")
        return result

    except Exception as exc:
        logger.error(f"[LLM] Analysis failed ({provider}/{model}): {type(exc).__name__}: {exc}")
        return None


def load_llm_config(session, tenant_id: int = None) -> Dict[str, str]:
    """
    Load LLM config with priority: Tenant fields > global SystemConfig.
    Tenant-level config allows per-tenant LLM keys (e.g. different providers).
    """
    from yads.models import SystemConfig, Tenant

    # 1. Global SystemConfig defaults
    config: Dict[str, str] = {}
    for k in ["LLM_PROVIDER", "LLM_API_URL", "LLM_API_KEY", "LLM_MODEL", "LLM_TIMEOUT"]:
        row = session.get(SystemConfig, k)
        if row:
            config[k] = row.value

    # 2. Tenant-level overrides (higher priority)
    if tenant_id:
        tenant = session.get(Tenant, tenant_id)
        if tenant:
            if tenant.llm_provider:
                config["LLM_PROVIDER"] = tenant.llm_provider
            if tenant.llm_api_url:
                config["LLM_API_URL"] = tenant.llm_api_url
            if tenant.llm_api_key:
                config["LLM_API_KEY"] = tenant.llm_api_key
            if tenant.llm_model:
                config["LLM_MODEL"] = tenant.llm_model

    return config
