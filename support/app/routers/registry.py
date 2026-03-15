"""
Docker Registry viewer — lists repositories, tags, sizes, creation dates,
deployment status (via Docker socket) and purge capability.

Env vars:
  REGISTRY_URL   — e.g. https://registry.yads-security.com
  REGISTRY_USER  — registry username
  REGISTRY_PASS  — registry password
  DOCKER_SOCKET  — path to Docker socket (default: /var/run/docker.sock)
"""
import os
import re
import httpx
from datetime import datetime
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from app.routers.ui import templates
from app.routers.admin_keys import _check_ip

router = APIRouter(prefix="/registry", tags=["registry"])

REGISTRY_URL   = os.getenv("REGISTRY_URL",  "https://registry.yads-security.com")
REGISTRY_USER  = os.getenv("REGISTRY_USER", "")
REGISTRY_PASS  = os.getenv("REGISTRY_PASS", "")
DOCKER_SOCKET  = os.getenv("DOCKER_SOCKET", "/var/run/docker.sock")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _auth():
    return (REGISTRY_USER, REGISTRY_PASS) if REGISTRY_USER and REGISTRY_PASS else None


async def _fetch(client: httpx.AsyncClient, path: str) -> dict:
    r = await client.get(f"{REGISTRY_URL}/v2/{path}", auth=_auth(), timeout=10)
    r.raise_for_status()
    return r.json()


def _fmt_size(b: int) -> str:
    if b >= 1_073_741_824: return f"{b / 1_073_741_824:.1f} GB"
    if b >= 1_048_576:     return f"{b / 1_048_576:.1f} MB"
    return f"{b / 1024:.1f} KB"


def _fmt_date(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return iso[:19]


async def _get_deployed_digests() -> set[str]:
    """Query Docker Swarm services via socket and return all deployed sha256 digests."""
    deployed = set()
    if not os.path.exists(DOCKER_SOCKET):
        return deployed
    try:
        transport = httpx.AsyncHTTPTransport(uds=DOCKER_SOCKET)
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost", timeout=5) as dc:
            r = await dc.get("/v1.41/services")
            if r.status_code != 200:
                return deployed
            for svc in r.json():
                img = svc.get("Spec", {}).get("TaskTemplate", {}).get("ContainerSpec", {}).get("Image", "")
                # image format: name:tag@sha256:abc123...
                m = re.search(r'@sha256:([a-f0-9]+)', img)
                if m:
                    deployed.add("sha256:" + m.group(1))
    except Exception:
        pass
    return deployed


async def _get_tag_info(client: httpx.AsyncClient, repo: str, tag: str) -> dict:
    try:
        r = await client.get(
            f"{REGISTRY_URL}/v2/{repo}/manifests/{tag}",
            auth=_auth(),
            headers={"Accept": "application/vnd.docker.distribution.manifest.v2+json"},
            timeout=10,
        )
        r.raise_for_status()
        manifest = r.json()
        full_digest = r.headers.get("Docker-Content-Digest", "")
        digest_short = full_digest[7:19] if full_digest.startswith("sha256:") else "—"
        total_size = sum(layer.get("size", 0) for layer in manifest.get("layers", []))
        config_digest = manifest.get("config", {}).get("digest", "")

        created = "—"
        if config_digest:
            try:
                cr = await client.get(f"{REGISTRY_URL}/v2/{repo}/blobs/{config_digest}", auth=_auth(), timeout=10)
                cr.raise_for_status()
                raw = cr.json().get("created", "")
                created = _fmt_date(raw) if raw else "—"
            except Exception:
                pass

        return {
            "tag": tag,
            "full_digest": full_digest,
            "digest_short": digest_short,
            "size_bytes": total_size,
            "size_fmt": _fmt_size(total_size) if total_size else "—",
            "created": created,
        }
    except Exception as e:
        return {"tag": tag, "full_digest": "", "digest_short": "—",
                "size_bytes": 0, "size_fmt": "—", "created": f"Error: {e}"}


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/", response_class=HTMLResponse)
async def registry_overview(request: Request, _: None = Depends(_check_ip)):
    repos_data = []
    error = None

    deployed_digests = await _get_deployed_digests()
    socket_available = os.path.exists(DOCKER_SOCKET)

    try:
        async with httpx.AsyncClient(verify=True) as client:
            catalog = await _fetch(client, "_catalog")
            repositories = sorted(catalog.get("repositories", []))

            for repo in repositories:
                try:
                    tags_resp = await _fetch(client, f"{repo}/tags/list")
                    tags = tags_resp.get("tags") or []

                    def _sort_key(t: str):
                        if t == "latest": return (1, [9999])
                        parts = []
                        for p in t.split("."):
                            try:   parts.append(int(p))
                            except ValueError: parts.append(0)
                        return (0, parts)

                    tag_infos = []
                    for tag in sorted(tags, key=_sort_key, reverse=True):
                        info = await _get_tag_info(client, repo, tag)
                        in_use = bool(info["full_digest"] and info["full_digest"] in deployed_digests)
                        # purgeable: not in use, not latest tag
                        purgeable = not in_use and tag != "latest" and bool(info["full_digest"])
                        info["in_use"] = in_use
                        info["purgeable"] = purgeable
                        tag_infos.append(info)

                    total_unique = sum(t["size_bytes"] for t in tag_infos if t["tag"] != "latest")
                    in_use_count = sum(1 for t in tag_infos if t["in_use"])
                    repos_data.append({
                        "name": repo,
                        "tag_count": len(tags),
                        "in_use_count": in_use_count,
                        "tags": tag_infos,
                        "total_size": _fmt_size(total_unique) if total_unique else "—",
                    })
                except Exception as e:
                    repos_data.append({"name": repo, "tag_count": 0, "in_use_count": 0,
                                       "tags": [], "total_size": "—", "error": str(e)})

    except Exception as e:
        error = str(e)

    return templates.TemplateResponse("registry.html", {
        "request": request,
        "repos": repos_data,
        "registry_url": REGISTRY_URL,
        "error": error,
        "socket_available": socket_available,
    })


class PurgeRequest(BaseModel):
    repo: str
    digest: str  # full sha256:... digest


@router.post("/purge", response_class=JSONResponse)
async def purge_tag(body: PurgeRequest, _: None = Depends(_check_ip)):
    if not body.digest.startswith("sha256:"):
        raise HTTPException(400, "Invalid digest format")

    # Safety: refuse to purge currently deployed images
    deployed = await _get_deployed_digests()
    if body.digest in deployed:
        raise HTTPException(409, "Image is currently deployed — cannot purge")

    async with httpx.AsyncClient(verify=True) as client:
        url = f"{REGISTRY_URL}/v2/{body.repo}/manifests/{body.digest}"
        r = await client.delete(url, auth=_auth(), timeout=10)
        if r.status_code in (200, 202):
            return {"ok": True}
        raise HTTPException(r.status_code, f"Registry DELETE returned {r.status_code}: {r.text[:200]}")
