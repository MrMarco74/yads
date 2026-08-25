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
