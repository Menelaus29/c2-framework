import asyncio
import platform
import pytest

from fastapi.testclient import TestClient

from common import message_format as mf
from common.crypto import get_session_key
from server.command_queue import CommandQueue
from server.session_manager import SessionManager
from server.storage import Database
from server.server_main import app


# Fixtures
@pytest.fixture(scope='module')
def event_loop():
    # Provide a single event loop shared across all module-scoped async fixtures.
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope='module')
async def db():
    # In-memory SQLite DB — discarded after the test module finishes.
    database = Database(db_path=':memory:')
    await database.__aenter__()
    yield database
    await database.__aexit__(None, None, None)


@pytest.fixture(scope='module')
async def server_state(db):
    # Initialise shared server state and override app globals before tests run.
    import server.server_main as srv

    srv.db          = db
    srv.session_mgr = SessionManager()
    srv.cmd_queue   = CommandQueue()

    # Prevent lifespan from overwriting our test instances
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _noop_lifespan(app):
        yield

    app.router.lifespan_context = _noop_lifespan

    yield {
        'db':          db,
        'session_mgr': srv.session_mgr,
        'cmd_queue':   srv.cmd_queue,
    }


@pytest.fixture(scope='module')
def client(server_state):
    # TestClient wraps the FastAPI app without starting a real server.
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


# Helpers
KEY = get_session_key()

def _post(client: TestClient, payload: dict) -> dict:
    # Pack, POST to /beacon, unpack and return the response dict.
    raw      = mf.pack(payload, KEY)
    response = client.post(
        '/beacon',
        content      = raw,
        headers      = {'Content-Type': 'application/octet-stream'},
    )
    assert response.status_code == 200, \
        f"FAIL: expected HTTP 200, got {response.status_code}: {response.text}"
    return mf.unpack(response.content, KEY)


def _checkin(client: TestClient) -> str:
    # Send a CHECKIN and return the assigned session_id.
    payload  = mf.build_checkin(
        hostname   = 'test-host',
        username   = 'test-user',
        os_info    = f'{platform.system()} test',
        agent_ver  = '1.0.0',
        jitter_pct = 20,
    )
    response = _post(client, payload)
    session_id = (
        response.get('session_id') or
        response.get('payload', {}).get('session_id')
    )
    assert session_id, "FAIL: CHECKIN response missing session_id"
    return session_id


# Tests
class TestIntegration:

    def test_01_checkin_returns_session_id(self, client, server_state):
        # CHECKIN must return a valid session_id.
        session_id = _checkin(client)
        assert isinstance(session_id, str),  "FAIL: session_id must be a string"
        assert len(session_id) == 36,        "FAIL: session_id must be a UUID"
        print(f"\n  [OK] checkin returned session_id: {session_id}")

    @pytest.mark.asyncio    
    async def test_02_task_dispatch_and_result(self, client, server_state):
        # Operator enqueues whoami; agent receives TASK_DISPATCH and returns TASK_RESULT.
        db        = server_state['db']
        cmd_queue = server_state['cmd_queue']

        session_id = _checkin(client)

        # Operator enqueues task
        task_id = await cmd_queue.enqueue_task(session_id, 'whoami', [], 10, db)

        assert task_id, "FAIL: enqueue_task did not return a task_id"

        # Agent sends TASK_PULL — should receive TASK_DISPATCH
        pull     = mf.build_task_pull(session_id)
        response = _post(client, pull)

        assert response.get('msg_type') == mf.MSG_TASK_DISPATCH, \
            f"FAIL: expected TASK_DISPATCH, got {response.get('msg_type')}"

        inner = response.get('payload', {})
        assert inner.get('task_id')  == task_id,   "FAIL: wrong task_id in dispatch"
        assert inner.get('command')  == 'whoami',  "FAIL: wrong command in dispatch"
        print(f"\n  [OK] TASK_DISPATCH received for task_id: {task_id}")

        # Agent executes and sends TASK_RESULT
        result_payload = mf.build_task_result(
            session_id  = session_id,
            task_id     = task_id,
            stdout      = 'test-user\n',
            stderr      = '',
            exit_code   = 0,
            duration_ms = 42,
        )
        result_response = _post(client, result_payload)

        assert result_response.get('msg_type') == mf.MSG_TASK_RESULT, \
            f"FAIL: expected TASK_RESULT ack, got {result_response.get('msg_type')}"
        print(f"  [OK] TASK_RESULT acknowledged by server")

    @pytest.mark.asyncio
    async def test_03_result_stored_in_db(self, client, server_state):
        # Server must persist the TaskResult so db.get_results_for_session returns it.
        db        = server_state['db']
        cmd_queue = server_state['cmd_queue']

        session_id = _checkin(client)

        # Enqueue and dispatch a task
        task_id = await cmd_queue.enqueue_task(session_id, 'hostname', [], 10, db)

        pull = mf.build_task_pull(session_id)
        _post(client, pull)  # triggers TASK_DISPATCH and mark_dispatched

        # Send result
        result_payload = mf.build_task_result(
            session_id  = session_id,
            task_id     = task_id,
            stdout      = 'test-host\n',
            stderr      = '',
            exit_code   = 0,
            duration_ms = 15,
        )
        _post(client, result_payload)

        # Verify stored in DB
        results = await db.get_results_for_session(session_id)

        assert len(results) >= 1, \
            "FAIL: db.get_results_for_session returned no results"

        stored = next((r for r in results if r['task_id'] == task_id), None)
        assert stored is not None,          "FAIL: task_id not found in stored results"
        assert stored['exit_code'] == 0,    "FAIL: wrong exit_code stored"
        assert 'test-host' in (stored['stdout'] or ''), \
            "FAIL: stdout not stored correctly"
        print(f"\n  [OK] result stored in DB for task_id: {task_id}")

    @pytest.mark.asyncio
    async def test_04_blocked_command_returns_126(self, client, server_state):
        # Agent must return exit_code=126 when operator enqueues a blocked command.
        db        = server_state['db']
        cmd_queue = server_state['cmd_queue']

        session_id = _checkin(client)

        # Enqueue a blocked command
        task_id = await cmd_queue.enqueue_task(session_id, 'reg', [], 10, db)

        # Agent receives dispatch
        pull     = mf.build_task_pull(session_id)
        response = _post(client, pull)

        assert response.get('msg_type') == mf.MSG_TASK_DISPATCH, \
            "FAIL: expected TASK_DISPATCH for blocked command"

        inner   = response.get('payload', {})
        command = inner.get('command')
        args    = inner.get('args', [])

        # Simulate agent-side executor blocklist check
        from agent.executor import execute
        import uuid
        result = execute(str(uuid.uuid4()), command, args, 10)

        assert result.exit_code == 126, \
            f"FAIL: blocked command should return exit_code 126, got {result.exit_code}"
        assert result.stderr == 'BLOCKED: prohibited command', \
            f"FAIL: wrong stderr for blocked command: {result.stderr}"

        # Agent sends result back
        result_payload = mf.build_task_result(
            session_id  = session_id,
            task_id     = task_id,
            stdout      = result.stdout,
            stderr      = result.stderr,
            exit_code   = result.exit_code,
            duration_ms = result.duration_ms,
        )
        result_response = _post(client, result_payload)

        assert result_response.get('msg_type') == mf.MSG_TASK_RESULT, \
            "FAIL: expected TASK_RESULT ack after blocked command"
        print(f"\n  [OK] blocked command 'reg' returned exit_code 126")