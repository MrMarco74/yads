"""
Dormant Domain Detector
========================
Recon module that flags targets showing signs of long-term abandonment --
domains still registered/resolving/monitored but with no meaningful
activity ("registered but unused"). It does no *unconditional* network I/O
of its own: mostly a pure analysis pass over data already collected by
other modules (web_analyzer, ssl_scanner, dns_scanner/subdomain_scanner,
catchall_detector, dsgvo_scanner, wayback_scanner, analytics_correlator)
and the ChangeEvent history -- so it's free to run and safe to leave on by
default. The one exception is an optional SearXNG search-engine query
(signal 8), which only fires if a tenant has explicitly configured a
SearXNG integration (see yads/api/routers/integrations.py) -- gracefully
skipped otherwise.

Weighted, score-based combination of 8 independent signals:

  Hard signals (2 points each -- YADS's own direct scan data, not
  dependent on third-party crawl completeness):
    1. stale_no_changes         -- no real ChangeEvent (any module) in
                                    90+ days, target itself old enough to judge.
    2. no_active_web_service    -- last web_analyzer result shows no live
                                    HTTP(S) service, or catchall_detector
                                    flagged a parked/generic page.
    3. cert_expired_or_expiring -- SSL cert already expired or expires
                                    within 30 days.
    4. dns_stale                -- no DNS-specific ChangeEvent (dns_scanner /
                                    subdomain_scanner) in 90+ days (narrower,
                                    partially overlaps #1 -- DNS records
                                    outliving all other activity is its own tell).
    5. no_impressum_found       -- dsgvo_scanner found no Impressum/legal-
                                    notice link (EU commercial sites are
                                    legally required to carry one).

  Soft signals (1 point each -- depend on third-party crawl completeness,
  can false-positive on legitimately private/robots-disallowed sites):
    6. wayback_never_crawled       -- wayback_scanner found zero archived
                                       captures ever.
    7. no_analytics_infrastructure -- analytics_correlator found zero
                                       tracker IDs (GA/GTM/etc) ever set up.
    8. not_indexed_by_search_engine -- SearXNG (if configured for the
                                       tenant) returns zero results for
                                       "site:{domain} impressum OR imprint".
                                       Distinguishes "checked, passed" from
                                       "not checked" (SearXNG unconfigured)
                                       via a `checked` field -- never scores
                                       when unchecked.

Max score = 5*2 + 3*1 = 13. is_dormant = score >= DORMANT_SCORE_THRESHOLD.
Marked, not deleted -- "for later analysis", per the recon report at
/dormant-domains.
"""
import logging
from datetime import datetime
from typing import Any, Dict, Optional

from sqlmodel import select

from yads.core.base import BaseScannerModule
from yads.models import Target, ScanResult, ChangeEvent
from yads.modules._shared_osint_utils import RateLimitedClient, search_searxng

logger = logging.getLogger(__name__)

STALE_DAYS_THRESHOLD = 90
CERT_EXPIRING_SOON_DAYS = 30
DORMANT_SCORE_THRESHOLD = 4

HARD_SIGNAL_POINTS = 2
SOFT_SIGNAL_POINTS = 1


class DormantDetectorScanner(BaseScannerModule):
    def __init__(self, db_session):
        super().__init__(db_session)
        self.http = RateLimitedClient(default_timeout=15)
        self.http.register_service("searxng", requests_per_minute=20)

    @property
    def module_name(self) -> str:
        return "dormant_detector"

    def run_scan(self, target: str, target_id: Optional[int] = None) -> Dict[str, Any]:
        logger.info(f"[DormantDetector] Analyzing {target}")
        now = datetime.utcnow()
        signals: Dict[str, Dict[str, Any]] = {}
        score = 0

        target_row = self.db.get(Target, target_id) if target_id else None
        target_created_at = target_row.created_at if target_row else None
        old_enough = target_created_at is not None and (now - target_created_at).days >= STALE_DAYS_THRESHOLD

        # -- Signal 1 (hard): no real change (any module) in a long time --
        last_change = self._latest_change_event(target_id, module_names=None)
        reference_time = last_change.created_at if last_change else target_created_at
        days_since_activity = (now - reference_time).days if reference_time else None
        stale_triggered = bool(
            old_enough and days_since_activity is not None and days_since_activity >= STALE_DAYS_THRESHOLD
        )
        if stale_triggered:
            score += HARD_SIGNAL_POINTS
        signals["stale_no_changes"] = {
            "triggered": stale_triggered,
            "days_since_last_change": days_since_activity,
        }

        # -- Signal 2 (hard): no active web service --
        web_res = self._latest_result(target_id, "web_analyzer")
        catchall_res = self._latest_result(target_id, "catchall_detector")
        no_web_service = False
        detail = None
        if web_res and web_res.data:
            status = web_res.data.get("status_code")
            if not status or status == 0:
                no_web_service = True
                detail = "No HTTP(S) response"
        if catchall_res and catchall_res.data and catchall_res.data.get("is_catch_all"):
            no_web_service = True
            detail = f"Catch-all/parked page ({catchall_res.data.get('detection_method')})"
        if no_web_service:
            score += HARD_SIGNAL_POINTS
        signals["no_active_web_service"] = {"triggered": no_web_service, "detail": detail}

        # -- Signal 3 (hard): cert expired or expiring soon --
        ssl_res = self._latest_result(target_id, "ssl_scanner")
        cert_triggered = False
        cert_detail = None
        if ssl_res and ssl_res.data and not ssl_res.data.get("error"):
            not_after = ssl_res.data.get("notAfter")
            if not_after:
                try:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - now).days
                    if days_left < CERT_EXPIRING_SOON_DAYS:
                        cert_triggered = True
                        cert_detail = f"Expired {abs(days_left)}d ago" if days_left < 0 else f"Expires in {days_left}d"
                except ValueError:
                    pass
        if cert_triggered:
            score += HARD_SIGNAL_POINTS
        signals["cert_expired_or_expiring"] = {"triggered": cert_triggered, "detail": cert_detail}

        # -- Signal 4 (hard): DNS records themselves haven't changed in a long time --
        last_dns_change = self._latest_change_event(target_id, module_names=["dns_scanner", "subdomain_scanner"])
        dns_reference = last_dns_change.created_at if last_dns_change else target_created_at
        dns_days_since = (now - dns_reference).days if dns_reference else None
        dns_stale_triggered = bool(old_enough and dns_days_since is not None and dns_days_since >= STALE_DAYS_THRESHOLD)
        if dns_stale_triggered:
            score += HARD_SIGNAL_POINTS
        signals["dns_stale"] = {"triggered": dns_stale_triggered, "days_since_last_dns_change": dns_days_since}

        # -- Signal 5 (hard): no Impressum / legal notice found --
        dsgvo_res = self._latest_result(target_id, "dsgvo_scanner")
        impressum_triggered = False
        if dsgvo_res and dsgvo_res.data and not dsgvo_res.data.get("error"):
            # `is False` (not `not ...get(...)`) so an old ScanResult predating
            # the impressum_found field (absent -> None) isn't misread as "found".
            impressum_triggered = dsgvo_res.data.get("impressum_found") is False
        if impressum_triggered:
            score += HARD_SIGNAL_POINTS
        signals["no_impressum_found"] = {"triggered": impressum_triggered}

        # -- Signal 6 (soft): never archived by Wayback Machine --
        wayback_res = self._latest_result(target_id, "wayback_scanner")
        wayback_triggered = False
        if wayback_res and wayback_res.data:
            total_captures = wayback_res.data.get("summary", {}).get("total_captures")
            if total_captures is not None and total_captures == 0:
                wayback_triggered = True
        if wayback_triggered:
            score += SOFT_SIGNAL_POINTS
        signals["wayback_never_crawled"] = {"triggered": wayback_triggered}

        # -- Signal 7 (soft): no analytics/tracking infrastructure ever set up --
        analytics_res = self._latest_result(target_id, "analytics_correlator")
        analytics_triggered = False
        if analytics_res and analytics_res.data is not None:
            trackers = analytics_res.data.get("trackers")
            if trackers is not None and len(trackers) == 0:
                analytics_triggered = True
        if analytics_triggered:
            score += SOFT_SIGNAL_POINTS
        signals["no_analytics_infrastructure"] = {"triggered": analytics_triggered}

        # -- Signal 8 (soft, opt-in): not indexed by SearXNG, if configured --
        searxng_signal: Dict[str, Any] = {"checked": False, "triggered": False, "detail": None}
        if target_row and target_row.tenant_id:
            results = search_searxng(
                self.db, target_row.tenant_id, f"site:{target} impressum OR imprint", self.http
            )
            if results is not None:
                searxng_signal["checked"] = True
                if len(results) == 0:
                    searxng_signal["triggered"] = True
                    searxng_signal["detail"] = "Not indexed by SearXNG (site:+impressum query)"
                    score += SOFT_SIGNAL_POINTS
        signals["not_indexed_by_search_engine"] = searxng_signal

        return {
            "is_dormant": score >= DORMANT_SCORE_THRESHOLD,
            "dormancy_score": score,
            "signals": signals,
            "last_activity_at": reference_time.isoformat() if reference_time else None,
        }

    def _latest_result(self, target_id: Optional[int], module_name: str) -> Optional[ScanResult]:
        if not target_id:
            return None
        return self.db.exec(
            select(ScanResult)
            .where(ScanResult.target_id == target_id, ScanResult.module_name == module_name)
            .order_by(ScanResult.scanned_at.desc())
        ).first()

    def _latest_change_event(self, target_id: Optional[int], module_names) -> Optional[ChangeEvent]:
        if not target_id:
            return None
        query = (
            select(ChangeEvent)
            .join(ScanResult, ChangeEvent.scan_result_id == ScanResult.id)
            .where(ScanResult.target_id == target_id)
        )
        if module_names:
            query = query.where(ScanResult.module_name.in_(module_names))
        query = query.order_by(ChangeEvent.created_at.desc())
        return self.db.exec(query).first()
