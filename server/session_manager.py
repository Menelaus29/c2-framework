import asyncio
import time
import uuid
from dataclasses import dataclass, field

from common.logger import get_logger
from server.storage import Database

logger = get_logger('session_manager')


# SessionState dataclass
@dataclass
class SessionState:
    session_id: str
    hostname:   str
    username:   str
    os:         str
    agent_ver:  str
    first_seen: float
    last_seen:  float
    jitter_pct: int
    active:     bool = True


# SessionManager
class SessionManager:
    # Holds all active sessions in memory, synced to DB on every mutation

    def __init__(self):
        self._sessions: dict[str, SessionState] = {}
        self._lock = asyncio.Lock()

    async def create_session(self, payload: dict, db: Database) -> str:
        # Create a new in-memory SessionState, persist to DB, return session_id
        session_id = str(uuid.uuid4())
        now        = time.time()

        state = SessionState(
            session_id = session_id,
            hostname   = payload.get('hostname', 'unknown'),
            username   = payload.get('username', 'unknown'),
            os         = payload.get('os', 'unknown'),
            agent_ver  = payload.get('agent_ver', 'unknown'),
            first_seen = now,
            last_seen  = now,
            jitter_pct = payload.get('jitter_pct', 0),
            active     = True,
        )

        async with self._lock:
            self._sessions[session_id] = state

        await db.insert_session(
            session_id = session_id,
            hostname   = state.hostname,
            username   = state.username,
            os         = state.os,
            agent_ver  = state.agent_ver,
            jitter_pct = state.jitter_pct,
        )

        logger.info('session created',
                    extra={'session_id': session_id, 'hostname': state.hostname})
        return session_id

    async def get_session(self, session_id: str) -> SessionState | None:
        # Return the in-memory SessionState for session_id, or None if not found
        async with self._lock:
            return self._sessions.get(session_id)

    async def update_last_seen(self, session_id: str, db: Database) -> None:
        # Update last_seen in memory and persist to DB
        async with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.last_seen = time.time()

        await db.update_last_seen(session_id)

    async def list_sessions(self) -> list[SessionState]:
        # Return all in-memory sessions ordered by last_seen descending
        async with self._lock:
            sessions = list(self._sessions.values())

        return sorted(sessions, key=lambda s: s.last_seen, reverse=True)

    async def deactivate_session(self, session_id: str, db: Database) -> None:
        # Mark session inactive in memory and persist to DB
        async with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.active = False

        await db.deactivate_session(session_id)
        logger.info('session deactivated', extra={'session_id': session_id})

    async def restore_from_db(self, db: Database) -> None:
        # Reload active sessions from DB into memory on server restart
        rows = await db.list_sessions()
        async with self._lock:
            for row in rows:
                if row['active']:
                    self._sessions[row['session_id']] = SessionState(
                        session_id = row['session_id'],
                        hostname   = row['hostname'],
                        username   = row['username'],
                        os         = row['os'],
                        agent_ver  = row['agent_ver'],
                        first_seen = row['first_seen'],
                        last_seen  = row['last_seen'],
                        jitter_pct = row['jitter_pct'],
                        active     = bool(row['active']),
                    )
        logger.info('sessions restored from DB', extra={'count': len(self._sessions)})


# Self-test
if __name__ == '__main__':
    import asyncio

    async def _test():
        print("Running session_manager self-test...")

        async with Database(':memory:') as db:
            mgr = SessionManager()

            # create_session
            payload = {
                'hostname':   'VICTIM-PC',
                'username':   'jdoe',
                'os':         'Windows 10 22H2',
                'agent_ver':  '1.0.0',
                'jitter_pct': 20,
            }
            sid = await mgr.create_session(payload, db)
            assert sid, "FAIL: create_session returned empty session_id"
            assert len(sid) == 36, "FAIL: session_id should be a UUID (36 chars)"
            print("  [OK] create_session")

            # get_session — known session
            state = await mgr.get_session(sid)
            assert state is not None,              "FAIL: get_session returned None for valid session_id"
            assert state.hostname   == 'VICTIM-PC',"FAIL: hostname mismatch"
            assert state.username   == 'jdoe',     "FAIL: username mismatch"
            assert state.jitter_pct == 20,         "FAIL: jitter_pct mismatch"
            assert state.active     is True,       "FAIL: new session should be active"
            print("  [OK] get_session")

            # get_session — unknown session
            missing = await mgr.get_session('nonexistent-id')
            assert missing is None, "FAIL: get_session should return None for unknown id"
            print("  [OK] get_session returns None for unknown session_id")

            # update_last_seen
            old_last_seen = state.last_seen
            await asyncio.sleep(0.05)  # ensure time advances
            await mgr.update_last_seen(sid, db)
            state = await mgr.get_session(sid)
            assert state.last_seen > old_last_seen, "FAIL: last_seen was not updated"
            print("  [OK] update_last_seen")

            # list_sessions
            payload2 = {**payload, 'hostname': 'VICTIM-PC-2', 'username': 'bob'}
            sid2     = await mgr.create_session(payload2, db)
            sessions = await mgr.list_sessions()
            assert len(sessions) == 2,            "FAIL: expected 2 sessions"
            assert sessions[0].last_seen >= sessions[1].last_seen, \
                "FAIL: list_sessions should be ordered by last_seen descending"
            print("  [OK] list_sessions")

            # deactivate_session
            await mgr.deactivate_session(sid, db)
            state = await mgr.get_session(sid)
            assert state.active is False, "FAIL: session should be inactive after deactivation"
            db_row = await db.get_session(sid)
            assert db_row['active'] == 0, "FAIL: DB active flag not set to 0"
            print("  [OK] deactivate_session")

            # restore_from_db
            mgr2 = SessionManager()
            await mgr2.restore_from_db(db)
            restored = await mgr2.list_sessions()
            # sid is inactive so only sid2 should be restored
            assert len(restored) == 1,              "FAIL: only 1 active session should be restored"
            assert restored[0].session_id == sid2,  "FAIL: wrong session restored"
            print("  [OK] restore_from_db")

        print("\nAll session_manager self-tests passed.")

    asyncio.run(_test())