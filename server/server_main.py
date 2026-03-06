import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from common import config
from common import message_format as mf
from common.logger import get_logger
from common.utils import CryptoError, ProtocolError
from server.command_queue import CommandQueue, TaskStatus
from server.session_manager import SessionManager
from server.storage import Database
from common.crypto import get_session_key

logger = get_logger('server')

app = FastAPI(docs_url=None, redoc_url=None)  # disable API docs in production


# Global state — initialised at startup, shared across all requests
db:        Database       = None
session_mgr: SessionManager = None
cmd_queue:   CommandQueue   = None


# Startup / shutdown
@app.on_event('startup')
async def startup():
    # Initialise DB, session manager, and command queue; restore active sessions.
    global db, session_mgr, cmd_queue

    db          = Database()
    await db.__aenter__()

    session_mgr = SessionManager()
    cmd_queue   = CommandQueue()

    await session_mgr.restore_from_db(db)
    logger.info('server started', extra={'port': config.SERVER_PORT})


@app.on_event('shutdown')
async def shutdown():
    # Close db connection cleanly on server shutdown
    if db:
        await db.__aexit__(None, None, None)
    logger.info('server stopped')


# Beacon endpoint
@app.post('/beacon')
async def beacon(request: Request) -> Response:
    # Handle all inbound agent messages: CHECKIN, TASK_PULL, TASK_RESULT
    source_ip = request.client.host
    raw_body  = await request.body()

    logger.info('beacon received', extra={
        'source_ip':    source_ip,
        'payload_size': len(raw_body),
    })

    # Step 2 — unpack and decrypt
    try:
        session_key = get_session_key()
        payload = mf.unpack(raw_body, session_key)
    except (ProtocolError, CryptoError) as e:
        logger.warning('unpack failed', extra={'source_ip': source_ip, 'reason': str(e)})
        return JSONResponse(status_code=400, content={'error': 'bad request'})

    msg_type   = payload.get('msg_type', '')
    session_id = payload.get('session_id')
    nonce      = payload.get('nonce', '')
    if not nonce:
        logger.warning('nonce not found', extra={'source_ip': source_ip})
        return JSONResponse(status_code=400, content={'error': 'bad request'})

    logger.info('beacon unpacked', extra={
        'source_ip':  source_ip,
        'msg_type':   msg_type,
        'session_id': session_id,
    })

    # Step 3 — nonce replay check
    if not await db.check_and_store_nonce(nonce):
        logger.warning('replay detected', extra={'nonce': nonce, 'source_ip': source_ip})
        return JSONResponse(status_code=409, content={'error': 'replay detected'})

    # Step 4 — dispatch by message type
    response_payload = await _dispatch(msg_type, session_id, payload, source_ip)

    if response_payload is None:
        return JSONResponse(status_code=400, content={'error': f'unknown msg_type: {msg_type}'})

    # Step 5 — pack and return encrypted response
    try:
        packed = mf.pack(response_payload, config.PRE_SHARED_KEY)
    except (ProtocolError, CryptoError) as e:
        logger.error('response pack failed', extra={'reason': str(e)})
        return JSONResponse(status_code=500, content={'error': 'internal error'})

    return Response(content=packed, media_type='application/octet-stream')


# Dispatch helper
async def _dispatch(msg_type: str, session_id: str,
                    payload: dict, source_ip: str) -> dict | None:
    # Route message to the correct handler and return the response payload dict

    if msg_type == mf.MSG_CHECKIN:
        return await _handle_checkin(payload, source_ip)

    if msg_type == mf.MSG_TASK_PULL:
        return await _handle_task_pull(session_id)

    if msg_type == mf.MSG_TASK_RESULT:
        return await _handle_task_result(session_id, payload)

    if msg_type == mf.MSG_HEARTBEAT:
        return await _handle_heartbeat(session_id)

    logger.warning('unknown msg_type', extra={'msg_type': msg_type})
    return None


# Message handlers
async def _handle_checkin(payload: dict, source_ip: str) -> dict:
    # Register new agent session and return assigned session_id
    inner      = payload.get('payload', {})
    session_id = await session_mgr.create_session(inner, db)

    logger.info('agent checked in', extra={
        'session_id': session_id,
        'hostname':   inner.get('hostname'),
        'source_ip':  source_ip,
    })

    resp = mf._base_payload(mf.MSG_CHECKIN, session_id=session_id)
    resp['payload'] = {'session_id': session_id, 'status': 'ok'}
    return resp


async def _handle_task_pull(session_id: str) -> dict:
    # Return next pending task for the session, or a no-task response
    if not session_id:
        return None

    session = await session_mgr.get_session(session_id)
    if not session:
        logger.warning('invalid session_id', extra={'session_id': session_id})
        return None

    await session_mgr.update_last_seen(session_id, db)

    task = await cmd_queue.peek_task(session_id, db=db)

    if task:
        await cmd_queue.mark_dispatched(task.task_id, db)
        resp = mf._base_payload(mf.MSG_TASK_DISPATCH, session_id=session_id)
        resp['payload'] = {
            'task_id':   task.task_id,
            'command':   task.command,
            'args':      task.args,
            'timeout_s': task.timeout_s,
        }
        logger.info('task dispatched', extra={
            'session_id': session_id,
            'task_id':    task.task_id,
            'command':    task.command,
        })
    else:
        # No pending task — agent continues beacon loop
        resp = mf._base_payload(mf.MSG_TASK_PULL, session_id=session_id)
        resp['payload'] = {'status': 'no_task'}

    return resp


async def _handle_task_result(session_id: str, payload: dict) -> dict:
    # Store task result and mark task complete
    if not session_id:
        return None

    session = await session_mgr.get_session(session_id)
    if not session:
        logger.warning('invalid session_id', extra={'session_id': session_id})
        return None

    inner = payload.get('payload', {})
    task_id = inner.get('task_id')
    if task_id:
        await cmd_queue.mark_complete(task_id, inner, db)
        logger.info('task result received', extra={
            'session_id': session_id,
            'task_id':    task_id,
            'exit_code':  inner.get('exit_code'),
        })

    resp = mf._base_payload(mf.MSG_TASK_RESULT, session_id=session_id)
    resp['payload'] = {'status': 'received', 'task_id': task_id}
    return resp


async def _handle_heartbeat(session_id: str) -> dict:
    # Update last_seen and acknowledge heartbeat
    if not session_id:
        return None

    session = await session_mgr.get_session(session_id)
    if not session:
        logger.warning('invalid session_id', extra={'session_id': session_id})
        return None

    await session_mgr.update_last_seen(session_id, db)

    resp = mf._base_payload(mf.MSG_HEARTBEAT, session_id=session_id)
    resp['payload'] = {'status': 'ok'}
    return resp


# Catch-all — return 404 for any path other than /beacon
@app.api_route('/{path:path}', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
async def catch_all(path: str) -> JSONResponse:
    # Reject all non-beacon paths to reduce attack surface.
    logger.warning('unexpected path', extra={'path': path})
    return JSONResponse(status_code=404, content={'error': 'not found'})


# Entry point
if __name__ == '__main__':
    uvicorn.run(
        'server.server_main:app',
        host        = '0.0.0.0',
        port        = config.BACKEND_PORT,   # 8443 — sits behind Nginx on 443
        ssl_keyfile  = config.TLS_CERT_PATH.replace('.crt', '.key'),
        ssl_certfile = config.TLS_CERT_PATH,
        log_level   = config.LOG_LEVEL.lower(),
    )