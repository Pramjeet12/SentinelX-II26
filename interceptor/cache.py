"""SQLite cache for domain scores and event logging."""

import aiosqlite
import time
import config


async def init_db():
    """Create tables if they don't exist."""
    async with aiosqlite.connect(config.DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS domain_cache (
                domain      TEXT PRIMARY KEY,
                score       REAL NOT NULL,
                reasons     TEXT NOT NULL DEFAULT '[]',
                verdict     TEXT NOT NULL,
                created_at  REAL NOT NULL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS event_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   REAL NOT NULL,
                domain      TEXT NOT NULL,
                full_url    TEXT,
                score       REAL,
                verdict     TEXT NOT NULL,
                source      TEXT DEFAULT 'dns'
            )
        """)
        await db.commit()


async def get_cached_score(domain: str) -> dict | None:
    """Return cached score if fresh, else None."""
    async with aiosqlite.connect(config.DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT score, reasons, verdict, created_at FROM domain_cache WHERE domain = ?",
            (domain,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        age = time.time() - row["created_at"]
        if age > config.CACHE_TTL_SECONDS:
            return None  # expired
        return {
            "score": row["score"],
            "reasons": row["reasons"],
            "verdict": row["verdict"],
        }


async def set_cached_score(domain: str, score: float, reasons: str, verdict: str):
    """Insert or update cached score."""
    async with aiosqlite.connect(config.DB_PATH) as db:
        await db.execute(
            """INSERT INTO domain_cache (domain, score, reasons, verdict, created_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(domain) DO UPDATE SET
                   score=excluded.score,
                   reasons=excluded.reasons,
                   verdict=excluded.verdict,
                   created_at=excluded.created_at""",
            (domain, score, reasons, verdict, time.time()),
        )
        await db.commit()


async def log_event(domain: str, score: float | None, verdict: str, full_url: str | None = None):
    """Log a DNS interception event."""
    async with aiosqlite.connect(config.DB_PATH) as db:
        await db.execute(
            "INSERT INTO event_log (timestamp, domain, full_url, score, verdict) VALUES (?, ?, ?, ?, ?)",
            (time.time(), domain, full_url, score, verdict),
        )
        await db.commit()


async def get_recent_events(limit: int = 50) -> list[dict]:
    """Return recent events for the UI."""
    async with aiosqlite.connect(config.DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM event_log ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
