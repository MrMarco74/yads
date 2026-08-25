"""
Broker queue operations.

The older UI purge paths (queue.py's /purge, and the pause/stop handlers)
manipulated a Redis list named "celery" directly. That is a no-op against the
production RabbitMQ broker (BROKER_URL=amqp://...), so paused/stopped scan
backlogs were never actually cleared — they accumulated in RabbitMQ across
pause/resume cycles and drained later, re-running modules that were never
selected for the newer targets. See the queue-backlog incident (2026-08-25).

purge_broker_queues() purges the real broker queues via a kombu channel, which
works for both the AMQP (RabbitMQ) and Redis transports.
"""

import logging

from kombu import Connection

logger = logging.getLogger(__name__)


def purge_broker_queues(broker_url: str, queue_names=("celery", "discovery")) -> int:
    """Purge all ready messages from the named broker queues.

    Best-effort: a failure purging one queue is logged and skipped so the rest
    still get purged, and a broker connection failure is swallowed (returns 0)
    rather than raised into the request handler that triggered the stop/pause.

    Returns the total number of messages removed across all queues.
    """
    purged = 0
    try:
        with Connection(broker_url) as conn:
            channel = conn.default_channel
            for queue_name in queue_names:
                try:
                    removed = channel.queue_purge(queue_name)
                    purged += int(removed or 0)
                except Exception as exc:
                    logger.warning(f"[Purge] queue_purge({queue_name}) failed: {exc}")
    except Exception as exc:
        logger.error(f"[Purge] broker connection failed, nothing purged: {exc}")
    return purged


def _message_task_args(msg):
    """Extract the run_all_scans positional args [target_id, domain, scan_types,
    tenant_id] from a kombu message, or None if it can't be decoded. Prefers the
    decoded payload; falls back to parsing the raw JSON body."""
    try:
        payload = msg.payload  # kombu decodes content-type/encoding for us
    except Exception:
        try:
            import json
            raw = msg.body
            if isinstance(raw, (bytes, bytearray)):
                raw = raw.decode("utf-8", errors="strict")
            payload = json.loads(raw)
        except Exception:
            return None
    if not isinstance(payload, (list, tuple)) or not payload:
        return None
    args = payload[0]
    if not isinstance(args, (list, tuple)):
        return None
    return args


def purge_broker_queue_for_tenant(broker_url: str, tenant_id, queue_names=("celery",)):
    """Purge only one tenant's pending scan tasks from the broker queues.

    RabbitMQ has no server-side selective purge, so this drains the ready
    messages (holding them unacked so they are not redelivered mid-operation),
    then acks/drops the ones belonging to `tenant_id` and reject-requeues the
    rest. A message that cannot be decoded is kept (requeued), never dropped —
    losing another tenant's scan is worse than leaving one item queued.

    Best-effort and not atomic: tasks a worker is already executing are not
    covered, and requeued messages lose their original ordering. Returns
    (purged_count, undo_tasks) where undo_tasks mirrors the args of the dropped
    tasks so the caller can offer an undo window.

    NOTE: this only sees messages that are *ready* in the broker; pausing the
    queue first gives the cleanest result by keeping the worker from competing
    for messages during the drain.
    """
    purged = 0
    undo_tasks = []
    try:
        with Connection(broker_url) as conn:
            channel = conn.default_channel
            for queue_name in queue_names:
                held = []
                try:
                    # Collect all ready messages first, unacked, so requeued
                    # ones can't be re-pulled within this same drain loop.
                    while True:
                        msg = channel.basic_get(queue_name, no_ack=False)
                        if msg is None:
                            break
                        held.append(msg)
                    for msg in held:
                        args = _message_task_args(msg)
                        msg_tenant = args[3] if args and len(args) > 3 else None
                        if args is not None and msg_tenant == tenant_id:
                            channel.basic_ack(msg.delivery_tag)
                            purged += 1
                            undo_tasks.append({
                                "target_id": args[0],
                                "domain": args[1] if len(args) > 1 else None,
                                "scan_types": args[2] if len(args) > 2 else None,
                                "tenant_id": msg_tenant,
                            })
                        else:
                            channel.basic_reject(msg.delivery_tag, requeue=True)
                except Exception as exc:
                    logger.warning(f"[Purge] tenant purge of {queue_name} failed: {exc}")
    except Exception as exc:
        logger.error(f"[Purge] broker connection failed, nothing purged: {exc}")
    return purged, undo_tasks
