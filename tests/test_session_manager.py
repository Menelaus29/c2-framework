import asyncio
import pytest
import uuid
import time

from server.storage import Database
from server.session_manager import SessionManager
from server.command_queue import CommandQueue, TaskStatus

# Fixtures
@pytest.fixture
async def db():
    # Provide a fresh in-memory DB for each test.
    async with Database(':memory:') as database:
        yield database


@pytest.fixture
async def session_mgr():
    return SessionManager()


@pytest.fixture
async def cmd_queue():
    return CommandQueue()


@pytest.fixture
def checkin_payload():
    return {
        'hostname':   'VICTIM-PC',
        'username':   'jdoe',
        'os':         'Windows 10 22H2',
        'agent_ver':  '1.0.0',
        'jitter_pct': 20,
    }


# create_session
async def test_create_session_returns_valid_uuid(db, session_mgr, checkin_payload):
    # create_session must return a valid UUID string.
    sid = await session_mgr.create_session(checkin_payload, db)

    assert sid is not None,    "FAIL: create_session returned None"
    assert isinstance(sid, str),"FAIL: session_id must be a string"
    parsed = uuid.UUID(sid)    
    assert str(parsed) == sid,     "FAIL: returned session_id is not a valid UUID"


async def test_create_session_stores_to_db(db, session_mgr, checkin_payload):
    # Session must be persisted to DB so it survives a server restart.
    sid = await session_mgr.create_session(checkin_payload, db)
    row = await db.get_session(sid)

    assert row is not None,                  "FAIL: session not found in DB after create"
    assert row['hostname']   == 'VICTIM-PC', "FAIL: hostname mismatch in DB"
    assert row['username']   == 'jdoe',      "FAIL: username mismatch in DB"
    assert row['jitter_pct'] == 20,          "FAIL: jitter_pct mismatch in DB"
    assert row['active']     == 1,           "FAIL: new session should be active in DB"


async def test_create_session_stores_to_memory(db, session_mgr, checkin_payload):
    # Session must also be available in-memory immediately after creation.
    sid   = await session_mgr.create_session(checkin_payload, db)
    state = await session_mgr.get_session(sid)

    assert state is not None,             "FAIL: session not found in memory after create"
    assert state.hostname   == 'VICTIM-PC',"FAIL: hostname mismatch in memory"
    assert state.active     is True,      "FAIL: new session should be active in memory"


async def test_create_session_unique_ids(db, session_mgr, checkin_payload):
    # Each create_session call must return a different session_id.
    sid1 = await session_mgr.create_session(checkin_payload, db)
    sid2 = await session_mgr.create_session(checkin_payload, db)

    assert sid1 != sid2, "FAIL: two sessions should not share the same session_id"


# get_session
async def test_get_session_returns_none_for_unknown_id(session_mgr):
    # get_session must return None for a session_id that was never created.
    result = await session_mgr.get_session('nonexistent-session-id')
    assert result is None, "FAIL: get_session should return None for unknown session_id"


async def test_get_session_returns_none_for_empty_string(session_mgr):
    result = await session_mgr.get_session('')
    assert result is None, "FAIL: get_session should return None for empty string"


async def test_get_session_returns_correct_state(db, session_mgr, checkin_payload):
    sid   = await session_mgr.create_session(checkin_payload, db)
    state = await session_mgr.get_session(sid)

    assert state.session_id == sid,          "FAIL: session_id mismatch"
    assert state.os         == 'Windows 10 22H2', "FAIL: os mismatch"
    assert state.agent_ver  == '1.0.0',      "FAIL: agent_ver mismatch"


# update_last_seen
async def test_update_last_seen_changes_timestamp(db, session_mgr, checkin_payload):
    # last_seen must be updated both in memory and in DB.
    sid           = await session_mgr.create_session(checkin_payload, db)
    state_before  = await session_mgr.get_session(sid)
    old_last_seen = state_before.last_seen

    await asyncio.sleep(0.05)  # ensure time advances before update
    await session_mgr.update_last_seen(sid, db)

    state_after = await session_mgr.get_session(sid)
    assert state_after.last_seen > old_last_seen, \
        "FAIL: last_seen was not updated in memory"


async def test_update_last_seen_persists_to_db(db, session_mgr, checkin_payload):
    sid      = await session_mgr.create_session(checkin_payload, db)
    row_before = await db.get_session(sid)
    old_ts   = row_before['last_seen']

    await asyncio.sleep(0.05)
    await session_mgr.update_last_seen(sid, db)

    row_after = await db.get_session(sid)
    assert row_after['last_seen'] > old_ts, \
        "FAIL: last_seen was not persisted to DB"


async def test_update_last_seen_unknown_session_does_not_raise(db, session_mgr):
    # Updating an unknown session should fail silently, not raise an exception.
    await session_mgr.update_last_seen('nonexistent-id', db)


# Nonce replay protection
async def test_nonce_first_call_returns_true(db):
    # First time a nonce is seen it must be accepted.
    nonce  = uuid.uuid4().hex
    result = await db.check_and_store_nonce(nonce)
    assert result is True, "FAIL: first nonce should return True"


async def test_nonce_second_call_returns_false(db):
    # Same nonce seen twice must be rejected on the second call.
    nonce = uuid.uuid4().hex
    await db.check_and_store_nonce(nonce)
    result = await db.check_and_store_nonce(nonce)
    assert result is False, "FAIL: replay nonce should return False"


async def test_nonce_different_nonces_both_accepted(db):
    # Two different nonces must both be accepted.
    nonce1 = uuid.uuid4().hex
    nonce2 = uuid.uuid4().hex

    assert await db.check_and_store_nonce(nonce1) is True, \
        "FAIL: first unique nonce should be accepted"
    assert await db.check_and_store_nonce(nonce2) is True, \
        "FAIL: second unique nonce should be accepted"


async def test_nonce_replay_across_10_unique_nonces(db):
    # All 10 unique nonces accepted; all 10 replays rejected.
    nonces = [uuid.uuid4().hex for _ in range(10)]

    for n in nonces:
        assert await db.check_and_store_nonce(n) is True, \
            f"FAIL: unique nonce {n} should be accepted"

    for n in nonces:
        assert await db.check_and_store_nonce(n) is False, \
            f"FAIL: replayed nonce {n} should be rejected"


# Command enqueue and peek_task
async def test_enqueue_and_peek_returns_task(db, session_mgr, cmd_queue, checkin_payload):
    # Enqueued task must be retrievable via peek_task.
    sid = await session_mgr.create_session(checkin_payload, db)
    tid = await cmd_queue.enqueue_task(sid, 'whoami', [], 30, db)

    task = await cmd_queue.peek_task(sid, db=db)

    assert task is not None,               "FAIL: peek_task returned None after enqueue"
    assert task.task_id == tid,            "FAIL: peek_task returned wrong task_id"
    assert task.command == 'whoami',       "FAIL: command mismatch"
    assert task.status  == TaskStatus.PENDING, "FAIL: task should be PENDING"


async def test_peek_task_is_non_destructive(db, session_mgr, cmd_queue, checkin_payload):
    # Calling peek_task twice must return the same task both times.
    sid = await session_mgr.create_session(checkin_payload, db)
    tid = await cmd_queue.enqueue_task(sid, 'ipconfig', [], 30, db)

    task1 = await cmd_queue.peek_task(sid, db=db)
    task2 = await cmd_queue.peek_task(sid, db=db)

    assert task1 is not None,             "FAIL: first peek returned None"
    assert task2 is not None,             "FAIL: second peek returned None"
    assert task1.task_id == task2.task_id,"FAIL: peek_task returned different tasks"


async def test_peek_task_returns_none_for_empty_queue(db, session_mgr, cmd_queue, checkin_payload):
    sid  = await session_mgr.create_session(checkin_payload, db)
    task = await cmd_queue.peek_task(sid, db=db)
    assert task is None, "FAIL: peek_task should return None when no tasks queued"


async def test_peek_task_returns_none_after_dispatch(db, session_mgr, cmd_queue, checkin_payload):
    # After mark_dispatched, peek_task must not return the same task again.
    sid = await session_mgr.create_session(checkin_payload, db)
    tid = await cmd_queue.enqueue_task(sid, 'hostname', [], 30, db)

    await cmd_queue.mark_dispatched(tid, db)
    task = await cmd_queue.peek_task(sid, db=db)

    assert task is None, "FAIL: dispatched task should not be returned by peek_task"


async def test_enqueue_task_persists_to_db(db, session_mgr, cmd_queue, checkin_payload):
    # Task must be findable in DB after enqueue, not just in memory.
    sid = await session_mgr.create_session(checkin_payload, db)
    tid = await cmd_queue.enqueue_task(sid, 'whoami', [], 30, db)

    row = await db.get_pending_task(sid)
    assert row is not None,           "FAIL: task not found in DB after enqueue"
    assert row['task_id'] == tid,     "FAIL: task_id mismatch in DB"
    assert row['command'] == 'whoami',"FAIL: command mismatch in DB"

async def test_enqueue_task_fifo_order(db, session_mgr, cmd_queue, checkin_payload):
    # Tasks must be returned in FIFO order.

    sid = await session_mgr.create_session(checkin_payload, db)

    tid1 = await cmd_queue.enqueue_task(sid, 'whoami', [], 30, db)
    tid2 = await cmd_queue.enqueue_task(sid, 'hostname', [], 30, db)

    task = await cmd_queue.peek_task(sid, db=db)

    assert task is not None, "FAIL: peek_task returned None"
    assert task.task_id == tid1, "FAIL: queue order incorrect (not FIFO)"


async def test_nonce_prune_old_entries(db):
    # Nonces older than 24h should be pruned and allowed again.

    nonce = uuid.uuid4().hex

    # Insert nonce with old timestamp
    old_time = time.time() - (25 * 60 * 60)

    await db._conn.execute(
        "INSERT INTO nonces (nonce, received_at) VALUES (?, ?)",
        (nonce, old_time)
    )
    await db._conn.commit()

    # Trigger pruning
    await db.prune_old_nonces()

    # Now the nonce should be accepted again
    result = await db.check_and_store_nonce(nonce)

    assert result is True, "FAIL: old nonce should be pruned and accepted again"