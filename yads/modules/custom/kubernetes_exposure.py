"""
Kubernetes & Container Exposure

Detects exposed Kubernetes and container infrastructure directly reachable from
the internet. Unauthenticated exposure of the Kubernetes API server, kubelet,
etcd, or Docker daemon gives an attacker full or partial cluster control — these
exposures are among the most critical findings in cloud infrastructure assessments.

What the module probes:
- Kubernetes API server: :6443, :8443 (TLS), :8080 (insecure)
- Kubelet: :10250 (authenticated RW), :10255 (read-only unauthenticated)
- etcd: :2379 (client), :2380 (peer)
- Docker daemon: :2375 (plain), :2376 (TLS)
- Container registries: :5000, :5001
- Known paths: /api/v1/namespaces, /healthz, /version, /v2/keys/ (etcd), etc.

Severity mapping:
- Unauthenticated K8s API server accessible → critical
- Docker daemon unauthenticated → critical
- etcd accessible → critical
- Kubelet read-only port accessible → high
- K8s dashboard (auth required) → medium
- Container registry accessible → medium
"""

import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from yads.core.base import BaseScannerModule

logger = logging.getLogger(__name__)

# Short timeouts — these ports will mostly refuse or timeout quickly
PROBE_TIMEOUT = 4

# (port, scheme, path, service_label, severity_if_open, detail_hint)
# severity is refined at runtime based on response content
_PROBES: List[Tuple[int, str, str, str, str, str]] = [
    # Kubernetes API server — TLS
    (6443, "https", "/api/v1/namespaces", "k8s_api_tls", "critical",
     "Kubernetes API server (TLS, port 6443) returned a response. "
     "If no authentication is required this gives full cluster control."),
    (6443, "https", "/healthz", "k8s_api_tls", "critical",
     "Kubernetes API server health endpoint accessible on port 6443."),
    (6443, "https", "/version", "k8s_api_tls", "critical",
     "Kubernetes API server version endpoint accessible on port 6443."),
    (8443, "https", "/api/v1/namespaces", "k8s_api_tls_alt", "critical",
     "Kubernetes API server on port 8443 returned a response for /api/v1/namespaces."),
    (8443, "https", "/healthz", "k8s_api_tls_alt", "critical",
     "Kubernetes API server health endpoint accessible on port 8443."),
    # Kubernetes insecure API (should never be public)
    (8080, "http", "/api/v1/namespaces", "k8s_api_insecure", "critical",
     "Kubernetes insecure API server on :8080 is accessible. This port provides "
     "unauthenticated access to the full Kubernetes API — treat as critical."),
    (8080, "http", "/healthz", "k8s_api_insecure", "critical",
     "Kubernetes insecure API healthz endpoint accessible on port 8080."),
    (8080, "http", "/version", "k8s_api_insecure", "critical",
     "Kubernetes insecure API version endpoint accessible on port 8080."),
    # HTTPS 443 paths
    (443, "https", "/api/v1/namespaces", "k8s_api_443", "critical",
     "Kubernetes API namespace list endpoint accessible on standard HTTPS port 443."),
    (443, "https", "/apis", "k8s_api_443", "critical",
     "Kubernetes API groups endpoint accessible on standard HTTPS port 443."),
    (443, "https", "/version", "k8s_api_443", "critical",
     "Kubernetes version endpoint accessible on port 443."),
    (443, "https", "/healthz", "k8s_healthz_443", "medium",
     "A /healthz endpoint is accessible on port 443 — may be a Kubernetes component."),
    # Kubelet
    (10250, "https", "/healthz", "kubelet_rw", "high",
     "Kubelet HTTPS API on port 10250 is accessible. This port allows pod execution "
     "and log retrieval. Authentication is required but misconfigurations are common."),
    (10250, "https", "/pods", "kubelet_rw", "high",
     "Kubelet /pods endpoint on port 10250 accessible — pod listing may work."),
    (10255, "http", "/healthz", "kubelet_readonly", "high",
     "Kubelet read-only API on port 10255 is accessible. This unauthenticated port "
     "exposes pod metadata, resource usage, and runtime information."),
    (10255, "http", "/pods", "kubelet_readonly", "high",
     "Kubelet read-only /pods endpoint on port 10255 accessible — pod listing works without auth."),
    # etcd
    (2379, "http", "/version", "etcd", "critical",
     "etcd HTTP endpoint on port 2379 is accessible. "
     "etcd stores all Kubernetes cluster state — read access leaks secrets; write access is catastrophic."),
    (2379, "http", "/v2/keys/", "etcd_v2", "critical",
     "etcd v2 key-value store accessible on port 2379 — cluster secrets may be readable."),
    (2379, "http", "/v3/cluster/member/list", "etcd_v3", "critical",
     "etcd v3 cluster member list accessible on port 2379."),
    (2379, "https", "/version", "etcd_tls", "critical",
     "etcd HTTPS endpoint on port 2379 accessible."),
    (2380, "http", "/members", "etcd_peer", "critical",
     "etcd peer port 2380 accessible from the internet — should be internal only."),
    # Docker daemon
    (2375, "http", "/v1.41/info", "docker_api", "critical",
     "Docker daemon API on port 2375 (unauthenticated, plain HTTP) is accessible. "
     "Full Docker API access allows spawning privileged containers and achieving host escape."),
    (2375, "http", "/info", "docker_api", "critical",
     "Docker daemon /info endpoint accessible on port 2375 — unauthenticated access."),
    (2375, "http", "/version", "docker_api", "critical",
     "Docker daemon version endpoint accessible on port 2375."),
    (2376, "https", "/info", "docker_api_tls", "critical",
     "Docker daemon TLS API on port 2376 returned a response. TLS does not guarantee "
     "authentication is enforced — verify client certificate requirements."),
    (2376, "https", "/version", "docker_api_tls", "critical",
     "Docker daemon TLS version endpoint accessible on port 2376."),
    # Container registries
    (5000, "http", "/v2/", "registry", "medium",
     "Container registry API endpoint accessible on port 5000. "
     "An unauthenticated registry leaks image inventory and may allow push access."),
    (5000, "http", "/v2/_catalog", "registry", "medium",
     "Container registry catalog accessible on port 5000 — image list may be readable."),
    (5001, "https", "/v2/", "registry_tls", "medium",
     "Container registry HTTPS endpoint accessible on port 5001."),
    (5001, "http", "/v2/", "registry_alt", "medium",
     "Container registry endpoint accessible on port 5001."),
]

# Signatures that confirm K8s/Docker identity in response bodies
_K8S_SIGNATURES = [
    b'"apiVersion"', b'"kind"', b'"namespaces"', b'"pods"',
    b'"selfLink"', b'"kubernetes"', b'Kubernetes', b'k8s.io',
    b'"nodeName"', b'"containerStatuses"',
]
_ETCD_SIGNATURES = [b'"etcdserver"', b'"cluster_version"', b'etcdcluster', b'"members"', b'"header"']
_DOCKER_SIGNATURES = [
    b'"ServerVersion"', b'"KernelVersion"', b'"Containers"',
    b'"DockerRootDir"', b'"NGoroutines"', b'"Driver"',
]
_REGISTRY_SIGNATURES = [b'"repositories"', b'"name"', b'"tags"', b'registry/2.0']


def _body_matches(body: bytes, sigs: List[bytes]) -> bool:
    return any(s in body for s in sigs)


class KubernetesExposure(BaseScannerModule):
    """
    Probes a target domain for exposed Kubernetes and container infrastructure.
    Checks API servers, kubelet, etcd, Docker daemon, and container registries
    across common ports and well-known paths, classifying exposures by blast radius.
    """

    @property
    def module_name(self) -> str:
        return "kubernetes_exposure"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        domain = (
            target.lower().strip()
            .removeprefix("https://").removeprefix("http://")
            .split("/")[0]
            .split(":")[0]
        )

        result: Dict[str, Any] = {
            "domain": domain,
            "exposures": [],
            "findings": [],
            "summary": {},
        }

        # Track which (port, service) combos we've already reported to avoid duplicates
        reported: set = set()

        for port, scheme, path, service, base_severity, detail in _PROBES:
            key = (port, service)
            if key in reported:
                continue  # already have a finding for this port+service

            url = f"{scheme}://{domain}:{port}{path}"
            resp_body, status_code, actual_url = self._probe(url)

            if resp_body is None:
                continue  # not reachable

            # Refine severity and confirm identity from response body
            confirmed = False
            severity = base_severity
            confirm_detail = ""

            if service in ("k8s_api_tls", "k8s_api_tls_alt", "k8s_api_insecure", "k8s_api_443"):
                if _body_matches(resp_body, _K8S_SIGNATURES):
                    confirmed = True
                    if status_code == 200 and b'"items"' in resp_body:
                        severity = "critical"
                        confirm_detail = (
                            "Response contains Kubernetes API data (items array) — "
                            "unauthenticated access is confirmed."
                        )
                    elif status_code in (401, 403):
                        severity = "medium"
                        confirm_detail = (
                            f"HTTP {status_code}: authentication IS required but the endpoint "
                            "is publicly reachable. Assess whether the auth mechanism is sufficient."
                        )
                    else:
                        confirm_detail = f"HTTP {status_code} with Kubernetes response body."
                elif status_code == 200:
                    confirmed = True
                    confirm_detail = f"HTTP 200 on {path} — content may be K8s related."
                elif status_code in (401, 403):
                    confirmed = True
                    severity = "medium"
                    confirm_detail = (
                        f"HTTP {status_code}: Kubernetes API appears accessible but requires auth. "
                        "The service should not be reachable from the internet at all."
                    )

            elif service in ("k8s_healthz_443",):
                if status_code == 200 and resp_body.strip() in (b"ok", b"OK"):
                    confirmed = True
                    severity = "medium"
                    confirm_detail = "Health endpoint returned 'ok' — may be a K8s or system component."

            elif service in ("kubelet_rw", "kubelet_readonly"):
                if status_code in (200, 401, 403) or _body_matches(resp_body, _K8S_SIGNATURES):
                    confirmed = True
                    if status_code == 200:
                        severity = "high"
                        confirm_detail = f"Kubelet endpoint returned HTTP 200 on {path}."
                    else:
                        confirm_detail = (
                            f"HTTP {status_code} — kubelet port is reachable. "
                            "Misconfigurations on this port are common."
                        )

            elif service in ("etcd", "etcd_v2", "etcd_v3", "etcd_tls", "etcd_peer"):
                if _body_matches(resp_body, _ETCD_SIGNATURES) or status_code == 200:
                    confirmed = True
                    if status_code == 200:
                        severity = "critical"
                        confirm_detail = "etcd responded with HTTP 200 — may be unauthenticated."
                    else:
                        confirm_detail = f"etcd port is reachable (HTTP {status_code})."

            elif service in ("docker_api", "docker_api_tls"):
                if _body_matches(resp_body, _DOCKER_SIGNATURES):
                    confirmed = True
                    severity = "critical"
                    confirm_detail = (
                        "Docker daemon API confirmed — response contains daemon info fields. "
                        "Full API access achieved without authentication."
                    )
                elif status_code == 200:
                    confirmed = True
                    confirm_detail = "Docker API port returned HTTP 200."

            elif service in ("registry", "registry_tls", "registry_alt"):
                if _body_matches(resp_body, _REGISTRY_SIGNATURES) or status_code in (200, 401):
                    confirmed = True
                    if status_code == 200 and _body_matches(resp_body, [b'"repositories"']):
                        severity = "medium"
                        confirm_detail = "Registry catalog returned image list — unauthenticated read access."
                    elif status_code == 401:
                        severity = "medium"
                        confirm_detail = (
                            "Container registry requires authentication but is publicly reachable. "
                            "Verify that credential stuffing / brute-force protections are in place."
                        )
                    else:
                        confirm_detail = f"Registry API endpoint accessible (HTTP {status_code})."

            if not confirmed:
                continue

            reported.add(key)
            exposure = {
                "port": port,
                "scheme": scheme,
                "service": service,
                "url": url,
                "http_status": status_code,
                "severity": severity,
                "detail": f"{detail} {confirm_detail}".strip(),
            }
            result["exposures"].append(exposure)
            result["findings"].append({
                "severity": severity,
                "title": f"Exposed {self._service_label(service)} on port {port}",
                "detail": exposure["detail"],
                "category": f"k8s_exposure_{service}",
            })

        # Summary
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "info": 0}
        for exp in result["exposures"]:
            sev = exp["severity"]
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        result["summary"] = {
            "domain": domain,
            "total_exposures": len(result["exposures"]),
            "critical": sev_counts["critical"],
            "high": sev_counts["high"],
            "medium": sev_counts["medium"],
            "findings_count": len(result["findings"]),
            "highest_severity": (
                "critical" if sev_counts["critical"] > 0 else
                "high" if sev_counts["high"] > 0 else
                "medium" if sev_counts["medium"] > 0 else
                "pass"
            ),
        }

        if not result["exposures"]:
            result["findings"].append({
                "severity": "info",
                "title": "No exposed Kubernetes or container infrastructure detected",
                "detail": (
                    "None of the commonly exposed Kubernetes/container service endpoints "
                    "returned confirmable responses on the probed ports. This does not guarantee "
                    "absence — non-standard ports or firewall-protected endpoints are not checked."
                ),
                "category": "k8s_no_exposure",
            })
            result["summary"]["highest_severity"] = "pass"

        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _probe(self, url: str):
        """
        Attempt an HTTP GET to url. Returns (body_bytes, status_code, final_url)
        or (None, None, None) if unreachable.
        """
        try:
            resp = requests.get(
                url,
                timeout=PROBE_TIMEOUT,
                verify=False,
                allow_redirects=False,
                headers={
                    "User-Agent": "Mozilla/5.0 YADS/KubeExposure",
                    "Accept": "application/json, */*",
                },
            )
            return resp.content[:32_768], resp.status_code, resp.url
        except requests.exceptions.SSLError:
            # TLS error on an HTTP probe — port is open but protocol mismatch
            # Try again without TLS verification details
            return None, None, None
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            return None, None, None
        except Exception as e:
            logger.debug(f"Probe failed for {url}: {e}")
            return None, None, None

    @staticmethod
    def _service_label(service: str) -> str:
        labels = {
            "k8s_api_tls": "Kubernetes API Server (TLS)",
            "k8s_api_tls_alt": "Kubernetes API Server (alt TLS port)",
            "k8s_api_insecure": "Kubernetes Insecure API Server",
            "k8s_api_443": "Kubernetes API Server (port 443)",
            "k8s_healthz_443": "Kubernetes health endpoint",
            "kubelet_rw": "Kubelet HTTPS API (RW)",
            "kubelet_readonly": "Kubelet read-only API",
            "etcd": "etcd HTTP endpoint",
            "etcd_v2": "etcd v2 key-value store",
            "etcd_v3": "etcd v3 endpoint",
            "etcd_tls": "etcd TLS endpoint",
            "etcd_peer": "etcd peer port",
            "docker_api": "Docker daemon API (unauthenticated)",
            "docker_api_tls": "Docker daemon TLS API",
            "registry": "Container registry",
            "registry_tls": "Container registry (TLS)",
            "registry_alt": "Container registry (alt port)",
        }
        return labels.get(service, service)
