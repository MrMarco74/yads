"""
Docker Registry viewer — lists repositories, tags, sizes and creation dates
from the private YADS registry.

Credentials come from env vars:
  REGISTRY_URL   — e.g. https://registry.yads-security.com  (no trailing slash)
  REGISTRY_USER  — registry username
  REGISTRY_PASS  — registry password
"""
import os
import httpx
from datetime import datetime, timezone
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse

from app.routers.ui import templates
from app.routers.admin_keys import require_admin_ip

router = APIRouter(prefix="/registry", tags=["registry"])

REGISTRY_URL  = os.getenv("REGISTRY_URL",  "https://registry.yads-security.com")
REGISTRY_USER = os.getenv("REGISTRY_USER", "")
REGISTRY_PASS = os.getenv("REGISTRY_PASS", "")


def _auth() -> tuple[str, str] | None:
    if REGISTRY_USER and REGISTRY_PASS:
        return (REGISTRY_USER, REGISTRY_PASS)
    return None


async def _fetch(client: httpx.AsyncClient, path: str) -> dict:
    url = f"{REGISTRY_URL}/v2/{path}"
    r = await client.get(url, auth=_auth(), timeout=10)
    r.raise_for_status()
    return r.json()


def _fmt_size(total_bytes: int) -> str:
    if total_bytes >= 1_073_741_824:
        return f"{total_bytes / 1_073_741_824:.1f} GB"
    if total_bytes >= 1_048_576:
        return f"{total_bytes / 1_048_576:.1f} MB"
    return f"{total_bytes / 1024:.1f} KB"


def _fmt_date(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return iso[:19]


async def _get_tag_info(client: httpx.AsyncClient, repo: str, tag: str) -> dict:
    """Return {digest_short, size_bytes, size_fmt, created} for a single tag."""
    try:
        r = await client.get(
            f"{REGISTRY_URL}/v2/{repo}/manifests/{tag}",
            auth=_auth(),
            headers={"Accept": "application/vnd.docker.distribution.manifest.v2+json"},
            timeout=10,
        )
        r.raise_for_status()
        manifest = r.json()
        digest_header = r.headers.get("Docker-Content-Digest", "")
        digest_short  = digest_header[7:19] if digest_header.startswith("sha256:") else "—"

        total_size = sum(layer.get("size", 0) for layer in manifest.get("layers", []))
        config_digest = manifest.get("config", {}).get("digest", "")

        created = "—"
        if config_digest:
            try:
                cr = await client.get(
                    f"{REGISTRY_URL}/v2/{repo}/blobs/{config_digest}",
                    auth=_auth(), timeout=10,
                )
                cr.raise_for_status()
                cfg = cr.json()
                raw = cfg.get("created", "")
                created = _fmt_date(raw) if raw else "—"
            except Exception:
                pass

        return {
            "tag": tag,
            "digest_short": digest_short,
            "size_bytes": total_size,
            "size_fmt": _fmt_size(total_size) if total_size else "—",
            "created": created,
        }
    except Exception as e:
        return {"tag": tag, "digest_short": "—", "size_bytes": 0, "size_fmt": "—", "created": f"Error: {e}"}


@router.get("/", response_class=HTMLResponse)
async def registry_overview(
    request: Request,
    _: None = Depends(require_admin_ip),
):
    repos_data = []
    error = None

    try:
        async with httpx.AsyncClient(verify=True) as client:
            catalog = await _fetch(client, "_catalog")
            repositories = sorted(catalog.get("repositories", []))

            for repo in repositories:
                try:
                    tags_resp = await _fetch(client, f"{repo}/tags/list")
                    tags = tags_resp.get("tags") or []

                    # Sort: latest first, then version tags descending
                    def _sort_key(t: str):
                        if t == "latest":
                            return (1, [9999])
                        parts = []
                        for p in t.split("."):
                            try:
                                parts.append(int(p))
                            except ValueError:
                                parts.append(0)
                        return (0, parts)

                    tags_sorted = sorted(tags, key=_sort_key, reverse=True)

                    tag_infos = []
                    for tag in tags_sorted:
                        info = await _get_tag_info(client, repo, tag)
                        tag_infos.append(info)

                    total_unique = sum(t["size_bytes"] for t in tag_infos if t["tag"] != "latest")
                    repos_data.append({
                        "name": repo,
                        "tag_count": len(tags),
                        "tags": tag_infos,
                        "total_size": _fmt_size(total_unique) if total_unique else "—",
                    })
                except Exception as e:
                    repos_data.append({"name": repo, "tag_count": 0, "tags": [], "total_size": "—", "error": str(e)})

    except Exception as e:
        error = str(e)

    return templates.TemplateResponse("registry.html", {
        "request": request,
        "repos": repos_data,
        "registry_url": REGISTRY_URL,
        "error": error,
    })
