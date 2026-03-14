"""
DiscoveryOrchestrator — drives recursive domain discovery sessions.

Flow:
  start_session(session_id)
    → seeds Depth-0 targets
    → calls _dispatch_depth(0)
  _dispatch_depth(depth)
    → queues run_discovery_scan for every target at this depth
    → waits (via Redis counter) for all to finish
    → calls _process_candidates(depth)
  _process_candidates(depth)
    → scores all pending candidates at this depth
    → accepts/rejects based on threshold
    → creates new Target rows for accepted
    → if depth+1 < max_depth → _dispatch_depth(depth+1)
"""

import logging
import time
from typing import List, Optional

from sqlmodel import Session, select

from yads.database import engine, redis_client
from yads.models import DiscoverySession, DiscoveryCandidate, DiscoveryDomainBlocklist, Target, ScanResult

# Scan types for below-threshold targets — same lightweight set as the discovery phase
DISCOVERY_SCAN_TYPES = ["dns_scanner", "ssl_scanner", "ct_monitor", "asn_scanner", "subdomain_scanner",
                        "cert_mismatch_scanner", "dns_history_scanner", "tld_scanner"]

logger = logging.getLogger("yads-discovery")

# Signal weights for relevance scoring
SIGNAL_WEIGHTS = {
    # ── structural signals ────────────────────────────────────────────────
    "subdomain_of_seed":     1.0,  # direct subdomain → always accept
    "same_tls_cert_san":     0.6,
    "ct_related_org":        0.55,
    "same_tracking_id":      0.7,
    "same_nameservers":      0.4,
    "same_asn":              0.35,
    "same_mx":               0.3,
    "string_similarity":     0.0,  # computed dynamically 0–0.5
    # ── passive hunter signals ────────────────────────────────────────────
    "cors_trusted_origin":   0.3,  # in CORS/CSP header — weak signal, CDNs/analytics appear here too
    "vt_passive_dns":        0.55, # VirusTotal historical resolution
    "spf_host":              0.5,  # authorised mail sender → same org
    "wayback_subdomain":     0.45, # historically reachable subdomain (passive hunter + dns_history)
    "favicon_match":         0.55, # identical favicon fingerprint → same codebase
    "srv_record":            0.4,  # SRV record points to this host
    "sitemap_reference":     0.25, # referenced in sitemap/robots.txt — also lists third-party domains
    # ── TLD scanner signals ───────────────────────────────────────────────────
    "tld_same_owner":        0.65, # same TLD variant resolves to same IP → almost certainly same org
    "tld_variant":           0.3,  # registered TLD variant, different/unknown owner
}


def _matches_blocklist(domain: str, patterns: List[str]) -> bool:
    for pattern in patterns:
        if pattern.startswith("*."):
            parent = pattern[2:]
            if domain == parent or domain.endswith("." + parent):
                return True
        elif domain == pattern:
            return True
    return False


def _string_similarity_score(candidate: str, seed_domains: List[str]) -> float:
    """
    Compute string similarity between candidate and seed domains.
    Returns 0.0 – 0.5.
    """
    import difflib
    best = 0.0
    c_base = candidate.split(".")[0]
    for seed in seed_domains:
        s_base = seed.split(".")[0]
        ratio = difflib.SequenceMatcher(None, c_base, s_base).ratio()
        if ratio > best:
            best = ratio
    # Scale 0-1 ratio to 0-0.5
    return best * 0.5


def _is_subdomain_of_any(domain: str, seed_domains: List[str]) -> bool:
    for seed in seed_domains:
        if domain == seed or domain.endswith("." + seed):
            return True
    return False


def score_candidate(domain: str, signals: List[str], seed_domains: List[str], string_sim: float = 0.0) -> float:
    """
    Compute relevance score from matched signal names.
    Returns capped at 1.0.
    """
    total = 0.0
    for sig in signals:
        total += SIGNAL_WEIGHTS.get(sig, 0.0)
    total += string_sim
    return min(1.0, total)


def _redis_session_key(session_id: int, depth: int) -> str:
    return f"discovery:{session_id}:depth:{depth}:pending"


class DiscoveryOrchestrator:
    def __init__(self, session_id: int):
        self.session_id = session_id

    def _get_session(self, db: Session) -> Optional[DiscoverySession]:
        return db.get(DiscoverySession, self.session_id)

    def start(self):
        """Entry point — seeds depth-0 targets and kicks off dispatch."""
        logger.info(f"[Discovery] Starting session {self.session_id}")
        with Session(engine) as db:
            sess = self._get_session(db)
            if not sess:
                logger.error(f"[Discovery] Session {self.session_id} not found")
                return

            sess.status = "running"
            from datetime import datetime
            sess.started_at = datetime.utcnow()
            db.add(sess)
            db.commit()
            db.refresh(sess)

            # Seed depth-0 targets
            for domain in sess.seed_domains:
                domain = domain.strip().lower()
                if not domain:
                    continue
                existing = db.exec(select(Target).where(Target.domain == domain)).first()
                if not existing:
                    t = Target(
                        domain=domain,
                        tenant_id=sess.tenant_id,
                        discovery_session_id=sess.id,
                        discovery_depth=0,
                        relevance_score=1.0,
                        discovery_signals=["seed"],
                        discovery_reason=f"Discovery session {sess.id} seed",
                    )
                    db.add(t)
                    db.commit()
                    db.refresh(t)
                else:
                    # Update existing with session linkage
                    existing.discovery_session_id = sess.id
                    existing.discovery_depth = 0
                    existing.relevance_score = 1.0
                    db.add(existing)
                    db.commit()

        self._dispatch_depth(0)

    def _dispatch_depth(self, depth: int):
        """Queue discovery scans for all targets at this depth."""
        from yads.worker_core import celery_app

        with Session(engine) as db:
            sess = self._get_session(db)
            if not sess or sess.status in ("stopped", "failed"):
                return

            sess.current_depth = depth
            db.add(sess)
            db.commit()

            targets = db.exec(
                select(Target).where(
                    Target.discovery_session_id == self.session_id,
                    Target.discovery_depth == depth,
                )
            ).all()

        if not targets:
            logger.info(f"[Discovery] No targets at depth {depth}, session {self.session_id} — finishing.")
            self._finish_session()
            return

        logger.info(f"[Discovery] Dispatching {len(targets)} targets at depth {depth}")

        # Use Redis counter to track when all tasks at this depth finish
        redis_key = _redis_session_key(self.session_id, depth)
        redis_client.set(redis_key, len(targets), ex=3600)

        for target in targets:
            celery_app.send_task(
                "yads.worker.run_discovery_scan",
                args=[self.session_id, target.id, target.domain, depth],
                queue="discovery",
            )

    def on_target_complete(self, depth: int):
        """Called by run_discovery_scan when one target finishes. Triggers processing when all done."""
        redis_key = _redis_session_key(self.session_id, depth)
        remaining = redis_client.decr(redis_key)
        logger.info(f"[Discovery] session={self.session_id} depth={depth} remaining={remaining}")

        if remaining <= 0:
            redis_client.delete(redis_key)
            self._process_candidates(depth)

    def _process_candidates(self, depth: int):
        """Score and accept/reject all pending candidates at this depth."""
        with Session(engine) as db:
            sess = self._get_session(db)
            if not sess or sess.status in ("stopped", "failed"):
                return

            candidates = db.exec(
                select(DiscoveryCandidate).where(
                    DiscoveryCandidate.session_id == self.session_id,
                    DiscoveryCandidate.depth == depth,
                    DiscoveryCandidate.status == "pending",
                )
            ).all()

            # Load tenant blocklist once for this batch
            blocklist_entries = db.exec(
                select(DiscoveryDomainBlocklist).where(
                    DiscoveryDomainBlocklist.tenant_id == sess.tenant_id
                )
            ).all()
            blocked_patterns = [e.pattern for e in blocklist_entries]

            accepted = 0
            rejected = 0

            for cand in candidates:
                # Skip silently if domain matches tenant blocklist
                if blocked_patterns and _matches_blocklist(cand.domain, blocked_patterns):
                    cand.status = "rejected"
                    cand.rejection_reason = "domain_blocked"
                    db.add(cand)
                    rejected += 1
                    sess.total_rejected += 1
                    continue

                # Check global limits
                if sess.total_accepted >= sess.max_targets:
                    cand.status = "rejected"
                    cand.rejection_reason = "max_targets_reached"
                    db.add(cand)
                    rejected += 1
                    continue

                # Check TLD filter
                if sess.allowed_tld_filter:
                    tld = cand.domain.rsplit(".", 1)[-1].lower()
                    if tld not in [t.lower() for t in sess.allowed_tld_filter]:
                        cand.status = "rejected"
                        cand.rejection_reason = "tld_filtered"
                        db.add(cand)
                        rejected += 1
                        continue

                # Compute string similarity
                string_sim = _string_similarity_score(cand.domain, sess.seed_domains)

                # Check if it's a direct subdomain of a seed
                is_sub = _is_subdomain_of_any(cand.domain, sess.seed_domains)
                signals = list(cand.matching_signals)
                if is_sub and "subdomain_of_seed" not in signals:
                    signals.append("subdomain_of_seed")

                score = score_candidate(cand.domain, signals, sess.seed_domains, string_sim)
                cand.relevance_score = score
                cand.matching_signals = signals

                if score >= sess.relevance_threshold or is_sub:
                    # Accept: create Target
                    existing = db.exec(select(Target).where(Target.domain == cand.domain)).first()
                    if existing:
                        cand.status = "duplicate"
                        db.add(cand)
                        continue

                    new_target = Target(
                        domain=cand.domain,
                        tenant_id=sess.tenant_id,
                        discovery_session_id=sess.id,
                        parent_target_id=cand.source_target_id,
                        discovery_depth=depth + 1,
                        relevance_score=score,
                        discovery_signals=signals,
                        discovery_reason=f"Discovery session {sess.id} — {', '.join(signals)}",
                    )
                    db.add(new_target)
                    db.commit()
                    db.refresh(new_target)

                    cand.status = "accepted"
                    db.add(cand)
                    accepted += 1
                    sess.total_accepted += 1
                else:
                    cand.status = "rejected"
                    cand.rejection_reason = f"score_below_threshold ({score:.2f} < {sess.relevance_threshold})"
                    db.add(cand)
                    rejected += 1
                    sess.total_rejected += 1

                    # Below threshold: still create a Target and queue a lightweight scan
                    # so the domain appears in the regular target list and gets basic intel.
                    # No recursion — it won't be dispatched via run_discovery_scan.
                    below_existing = db.exec(select(Target).where(Target.domain == cand.domain)).first()
                    if not below_existing:
                        below_target = Target(
                            domain=cand.domain,
                            tenant_id=sess.tenant_id,
                            discovery_session_id=sess.id,
                            parent_target_id=cand.source_target_id,
                            discovery_depth=depth + 1,
                            relevance_score=score,
                            discovery_signals=signals,
                            discovery_reason=f"Discovery session {sess.id} — below threshold, queued for basic scan",
                        )
                        db.add(below_target)
                        db.commit()
                        db.refresh(below_target)
                        from yads.worker_core import celery_app
                        celery_app.send_task(
                            "yads.worker.run_all_scans",
                            args=[below_target.id, cand.domain, DISCOVERY_SCAN_TYPES, sess.tenant_id],
                            queue="celery",
                        )
                        logger.info(f"[Discovery] Below-threshold {cand.domain} ({score:.2f}) queued for basic scan")

            sess.total_discovered += len(candidates)
            db.add(sess)
            db.commit()

        logger.info(f"[Discovery] depth={depth}: accepted={accepted} rejected={rejected}")

        # Recurse to next depth
        next_depth = depth + 1
        with Session(engine) as db:
            sess = self._get_session(db)
            if not sess or sess.status in ("stopped", "failed"):
                return
            if next_depth >= sess.max_depth:
                logger.info(f"[Discovery] Max depth {sess.max_depth} reached — finishing.")
                self._finish_session()
                return

        self._dispatch_depth(next_depth)

    def _finish_session(self):
        with Session(engine) as db:
            sess = self._get_session(db)
            if not sess:
                return
            from datetime import datetime
            sess.status = "completed"
            sess.finished_at = datetime.utcnow()
            db.add(sess)
            db.commit()
        logger.info(f"[Discovery] Session {self.session_id} completed.")
