# Note: subprocess execution paths (success, timeout, FileNotFoundError,
# generic exception) are covered by integration_test.py and live agent-server
# runs. Unit testing real subprocess behaviour adds OS-level complexity with
# minimal correctness value over integration testing.
import sys
import uuid
import pytest
from unittest.mock import patch
import subprocess

from agent.executor import execute, _is_blocked, TaskResult, MAX_OUTPUT
from common import config


def _id() -> str:
    """Generate a unique task ID for each test."""
    return str(uuid.uuid4())


# Platform-aware command helpers so tests run on both Windows and Linux

def echo_cmd() -> tuple[str, list]:
    """Return (command, args) for a simple echo."""
    if sys.platform == 'win32':
        return 'cmd', ['/c', 'echo hello']
    return 'echo', ['hello']


def sleep_cmd(seconds: int) -> tuple[str, list]:
    """Return (command, args) for a sleep that exceeds timeout."""
    if sys.platform == 'win32':
        return 'cmd', ['/c', f'ping -n {seconds + 1} 127.0.0.1']
    return 'sleep', [str(seconds)]


def exit_cmd(code: int) -> tuple[str, list]:
    """Return (command, args) that exits with a specific code."""
    if sys.platform == 'win32':
        return 'cmd', ['/c', f'exit /b {code}']
    return 'bash', ['-c', f'exit {code}']


class TestIsBlocked:

    def test_blocked_command_exact_match(self):
        # Every entry in BLOCKED_COMMANDS must be blocked exactly
        for cmd in config.BLOCKED_COMMANDS:
            assert _is_blocked(cmd), (
                f"'{cmd}' should be blocked but _is_blocked returned False"
            )

    def test_blocked_command_with_args(self):
        # 'reg query HKLM\\...' must be blocked because it starts with 'reg'
        assert _is_blocked('reg query HKLM\\Software')
        assert _is_blocked('schtasks /create /tn test')
        assert _is_blocked('nmap -sV 192.168.1.1')

    def test_blocked_command_case_insensitive(self):
        # Blocklist check must be case-insensitive
        assert _is_blocked('REG')
        assert _is_blocked('Nmap')
        assert _is_blocked('SCHTASKS')

    def test_allowed_command_not_blocked(self):
        assert not _is_blocked('whoami')
        assert not _is_blocked('echo')
        assert not _is_blocked('ipconfig')

    def test_empty_command_not_blocked(self):
        # Empty string is handled by the empty-command guard before blocklist
        # _is_blocked itself should return False for empty string
        assert not _is_blocked('')

    def test_partial_match_not_blocked(self):
        # 'registry_cleaner' starts with 'reg' but is not 'reg' or 'reg <space>...'
        # This verifies the startswith check requires a space separator
        assert not _is_blocked('registry_cleaner')
        assert not _is_blocked('schedule')


class TestExecuteEmptyCommand:

    def test_empty_string_returns_exit_126(self):
        result = execute(_id(), '', [], 5)
        assert result.exit_code == 126

    def test_empty_string_stderr_message(self):
        result = execute(_id(), '', [], 5)
        assert result.stderr == 'BLOCKED: empty command'

    def test_empty_string_stdout_is_empty(self):
        result = execute(_id(), '', [], 5)
        assert result.stdout == ''

    def test_whitespace_only_returns_exit_126(self):
        # '   '.strip() == '' so whitespace-only must also be blocked
        result = execute(_id(), '   ', [], 5)
        assert result.exit_code == 126

    def test_none_args_normalised(self):
        # None args must be treated as empty list — must not raise
        result = execute(_id(), '', None, 5)
        assert result.exit_code == 126

    def test_returns_task_result_dataclass(self):
        result = execute(_id(), '', [], 5)
        assert isinstance(result, TaskResult)

    def test_task_id_preserved(self):
        tid = _id()
        result = execute(_id(), '', [], 5)
        # task_id in result should match what was passed in
        result2 = execute(tid, '', [], 5)
        assert result2.task_id == tid

    def test_duration_ms_is_non_negative(self):
        result = execute(_id(), '', [], 5)
        assert result.duration_ms >= 0


class TestExecuteBlockedCommands:

    def test_blocked_command_returns_exit_126(self):
        result = execute(_id(), 'nmap', [], 5)
        assert result.exit_code == 126

    def test_blocked_command_stderr_message(self):
        result = execute(_id(), 'nmap', [], 5)
        assert result.stderr == 'BLOCKED: prohibited command'

    def test_blocked_command_stdout_is_empty(self):
        result = execute(_id(), 'nmap', [], 5)
        assert result.stdout == ''

    def test_all_blocked_commands_rejected(self):
        # Every entry in BLOCKED_COMMANDS must trigger exit_code 126
        for cmd in config.BLOCKED_COMMANDS:
            result = execute(_id(), cmd, [], 5)
            assert result.exit_code == 126, (
                f"'{cmd}' should be blocked but returned exit_code {result.exit_code}"
            )

    def test_blocked_command_with_args_rejected(self):
        result = execute(_id(), 'reg', ['query', 'HKLM\\Software'], 5)
        assert result.exit_code == 126

    def test_blocked_command_uppercase_rejected(self):
        result = execute(_id(), 'NMAP', [], 5)
        assert result.exit_code == 126

    def test_blocked_returns_task_result_dataclass(self):
        result = execute(_id(), 'nmap', [], 5)
        assert isinstance(result, TaskResult)


