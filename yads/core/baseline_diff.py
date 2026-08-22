"""
Generic "what changed since last time" utility, backed by BaselineSnapshot.

Any feature that needs point-in-time diffing (open ports, API endpoints,
whois/DNS ownership fields, wayback-discovered secrets, ...) stores its
current state under a stable `snapshot_key` and calls `diff_against_last`.
The snapshot is overwritten on every call — this is NOT a history table,
just "current vs. what we saw last time".
"""
from typing import Any, Dict, Iterable, Optional
from datetime import datetime

from sqlmodel import Session, select

from yads.models import BaselineSnapshot


def _as_set(items: Optional[Iterable[Any]]) -> set:
    return set(items or [])


def diff_against_last(
    session: Session,
    snapshot_key: str,
    new_items: Iterable[Any],
    tenant_id: Optional[int] = None,
    target_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Compare `new_items` (a list of hashable values, e.g. open ports or endpoint
    paths) against the last saved snapshot for this (tenant_id, target_id,
    snapshot_key), then overwrite the snapshot with `new_items`.

    Returns {"added": [...], "removed": [...], "unchanged": [...], "is_first": bool}.
    On the first-ever call for a key, `is_first` is True and everything is
    reported as "added" (nothing to diff against yet).
    """
    stmt = select(BaselineSnapshot).where(
        BaselineSnapshot.tenant_id == tenant_id,
        BaselineSnapshot.target_id == target_id,
        BaselineSnapshot.snapshot_key == snapshot_key,
    )
    row = session.exec(stmt).first()

    new_set = _as_set(new_items)
    old_set = _as_set(row.data.get("items")) if row else set()
    is_first = row is None

    result = {
        "added": sorted(new_set - old_set, key=str),
        "removed": sorted(old_set - new_set, key=str),
        "unchanged": sorted(new_set & old_set, key=str),
        "is_first": is_first,
    }

    if row is None:
        row = BaselineSnapshot(
            tenant_id=tenant_id,
            target_id=target_id,
            snapshot_key=snapshot_key,
            data={"items": sorted(new_set, key=str)},
        )
        session.add(row)
    else:
        row.data = {"items": sorted(new_set, key=str)}
        row.updated_at = datetime.utcnow()
        session.add(row)
    session.commit()

    return result
