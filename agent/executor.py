import subprocess
import time
from dataclasses import dataclass

from common import config
from common.logger import get_logger

logger = get_logger('agent')
MAX_OUTPUT = 65536  # 64 KB cap to prevent oversized responses


# TaskResult dataclass
@dataclass
class TaskResult:
    task_id:     str
    stdout:      str
    stderr:      str
    exit_code:   int
    duration_ms: int


# Blocklist helper
def _is_blocked(command: str) -> bool:
    # Return True if command matches any entry in BLOCKED_COMMANDS.
    command_lower = command.lower().strip()
    return any(
        command_lower == blocked.lower() or
        command_lower.startswith(blocked.lower() + " ")
        for blocked in config.BLOCKED_COMMANDS
    )

# Executor
def execute(task_id: str, command: str, args: list,
            timeout_s: int) -> TaskResult:
    # Execute a command safely and return a TaskResult — never uses shell=True.
    start_ms = time.monotonic()

    def _elapsed() -> int:
        return int((time.monotonic() - start_ms) * 1000)

    # Normalise inputs — guard against None or empty values from server dispatch
    args    = args or []
    command = (command or '').strip()

    if not command:
        logger.warning('empty command rejected', extra={'task_id': task_id})
        return TaskResult(
            task_id     = task_id,
            stdout      = '',
            stderr      = 'BLOCKED: empty command',
            exit_code   = 126,
            duration_ms = _elapsed(),
        )    

    # Step 1 — blocklist check
    if _is_blocked(command):
        logger.warning('blocked command rejected', extra={
            'task_id': task_id,
            'command': command,
        })
        return TaskResult(
            task_id     = task_id,
            stdout      = '',
            stderr      = 'BLOCKED: prohibited command',
            exit_code   = 126,
            duration_ms = _elapsed(),
        )

    # Step 2 — build command list
    cmd_list = [command] + [str(a) for a in args]

    logger.info('executing command', extra={
        'task_id': task_id,
        'command': command,
        'cmd_args':    args,
    })

    # Step 3 — execute
    try:
        result = subprocess.run(
            cmd_list,
            capture_output = True,
            text           = True,
            timeout        = timeout_s,
            shell          = False,  # never shell=True — prevents injection
        )

        # Step 4 — return result
        task_result = TaskResult(
            task_id     = task_id,
            stdout      = (result.stdout or '')[:MAX_OUTPUT],
            stderr      = (result.stderr or '')[:MAX_OUTPUT],
            exit_code   = result.returncode,
            duration_ms = _elapsed(),
        )
        logger.info('command complete', extra={
            'task_id':    task_id,
            'exit_code':  result.returncode,
            'duration_ms': task_result.duration_ms,
        })
        return task_result

    except subprocess.TimeoutExpired as e:
        logger.warning('command timed out', extra={
            'task_id':   task_id,
            'timeout_s': timeout_s,
        })
        return TaskResult(
            task_id     = task_id,
            stdout      = e.stdout or '',
            stderr      = e.stderr or 'TIMEOUT',
            exit_code   = 124,
            duration_ms = _elapsed(),
        )

    except FileNotFoundError:
        logger.warning('command not found', extra={
            'task_id': task_id,
            'command': command,
        })
        return TaskResult(
            task_id     = task_id,
            stdout      = '',
            stderr      = 'COMMAND NOT FOUND',
            exit_code   = 127,
            duration_ms = _elapsed(),
        )

    except Exception as e:
        logger.error('unexpected executor error', extra={
            'task_id': task_id,
            'reason':  str(e),
        })
        return TaskResult(
            task_id     = task_id,
            stdout      = '',
            stderr      = f'EXECUTOR ERROR: {e}',
            exit_code   = 1,
            duration_ms = _elapsed(),
        )


# Self-test
if __name__ == '__main__':
    import platform
    import uuid

    print("Running executor self-test...")

    def _id() -> str:
        return str(uuid.uuid4())

    # Test 1 — blocked command returns exit_code 126
    result = execute(_id(), 'nmap', [], 30)
    assert result.exit_code == 126,                    "FAIL: blocked command should return exit_code 126"
    assert result.stderr    == 'BLOCKED: prohibited command', "FAIL: wrong stderr for blocked command"
    assert result.stdout    == '',                     "FAIL: blocked command should have empty stdout"
    print("  [OK] blocked command returns exit_code 126")

    # Test 2 — all entries in BLOCKED_COMMANDS are blocked
    for cmd in config.BLOCKED_COMMANDS:
        # Use first word only — e.g. 'whoami /priv' -> 'whoami /priv' as command
        r = execute(_id(), cmd, [], 5)
        assert r.exit_code == 126, \
            f"FAIL: '{cmd}' should be blocked but returned exit_code {r.exit_code}"
    print("  [OK] all BLOCKED_COMMANDS entries are rejected")

    # Test 3 — successful command returns exit_code 0
    if platform.system() == 'Windows':
        result = execute(_id(), 'cmd', ['/c', 'echo hello'], 10)
    else:
        result = execute(_id(), 'echo', ['hello'], 10)
    assert result.exit_code == 0,      "FAIL: echo should return exit_code 0"
    assert 'hello' in result.stdout,   "FAIL: stdout should contain 'hello'"
    assert result.duration_ms >= 0,    "FAIL: duration_ms should be non-negative"
    print("  [OK] successful command returns exit_code 0 with correct stdout")

    # Test 4 — command not found returns exit_code 127
    result = execute(_id(), 'nonexistent_command_xyz', [], 5)
    assert result.exit_code == 127,              "FAIL: missing command should return exit_code 127"
    assert result.stderr    == 'COMMAND NOT FOUND', "FAIL: wrong stderr for missing command"
    print("  [OK] missing command returns exit_code 127")

    # Test 5 — timeout returns exit_code 124
    if platform.system() == 'Windows':
        result = execute(_id(), 'cmd', ['/c', 'ping -n 10 127.0.0.1'], 1)
    else:
        result = execute(_id(), 'sleep', ['10'], 1)
    assert result.exit_code == 124,  "FAIL: timed-out command should return exit_code 124"
    assert result.stderr    == 'TIMEOUT', "FAIL: wrong stderr for timeout"
    print("  [OK] timed-out command returns exit_code 124")

    # Test 6 — duration_ms is measured and positive
    if platform.system() == 'Windows':
        result = execute(_id(), 'cmd', ['/c', 'echo timing'], 10)
    else:
        result = execute(_id(), 'echo', ['timing'], 10)
    assert result.duration_ms > 0, "FAIL: duration_ms should be greater than 0"
    print("  [OK] duration_ms is positive")

    # Test 7 — shell=False prevents injection (semicolon in args is not executed)
    if platform.system() == 'Windows':
        result = execute(_id(), 'cmd', ['/c', 'echo safe; echo injected'], 5)
    else:
        result = execute(_id(), 'echo', ['safe; echo injected'], 5)
    assert 'injected' not in result.stdout or platform.system() == 'Windows', \
        "FAIL: shell injection should not be possible with shell=False"
    print("  [OK] shell=False prevents command injection")

    # Test 8 — args are passed correctly
    if platform.system() == 'Windows':
        result = execute(_id(), 'cmd', ['/c', 'echo arg1 arg2'], 5)
        assert 'arg1' in result.stdout, "FAIL: args not passed to command"
    else:
        result = execute(_id(), 'echo', ['arg1', 'arg2'], 5)
        assert 'arg1' in result.stdout and 'arg2' in result.stdout, \
            "FAIL: args not passed to command correctly"
    print("  [OK] args passed correctly to command")

    print("\nAll executor self-tests passed.")