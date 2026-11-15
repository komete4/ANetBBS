"""Database rate limits for public endpoints and protocol authentication."""

import random
import time

from sqlalchemy import delete, select, text, update

from ..models import ServiceRateBucket


def rate_window_now(executor):
    """Return the time for rate decisions, and occasionally purge expired rows."""
    now = int(time.time())
    if random.randrange(128) == 0:
        executor.execute(delete(ServiceRateBucket).where(ServiceRateBucket.expires_at <= now))
    return now


def lock_bucket(executor, key, now, seconds):
    """Acquire a bucket until transaction end, returning the current count.

    On PostgreSQL the upsert locks a single row. On SQLite it acquires a write
    transaction before any count-based admission decision is made.
    """
    executor.execute(text("""
        INSERT INTO service_rate_buckets (key, hits, expires_at)
        VALUES (:key, 0, :expires_at)
        ON CONFLICT (key) DO UPDATE SET
            hits = CASE WHEN service_rate_buckets.expires_at <= :now
                        THEN 0 ELSE service_rate_buckets.hits END,
            expires_at = CASE WHEN service_rate_buckets.expires_at <= :now
                              THEN :expires_at ELSE service_rate_buckets.expires_at END
    """), {'key': key, 'now': now, 'expires_at': now + seconds})
    return executor.execute(select(ServiceRateBucket.hits).where(
        ServiceRateBucket.key == key)).scalar_one()


def count_hit(executor, key):
    executor.execute(update(ServiceRateBucket).where(ServiceRateBucket.key == key)
                     .values(hits=ServiceRateBucket.hits + 1))
