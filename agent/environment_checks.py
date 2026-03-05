import os
import platform
import sys

from common import config
from common.logger import get_logger

logger = get_logger('agent')


# Internal check helpers
def _check_lab_mode() -> None:
    # Exit immediately if LAB_MODE env var is not set to '1'.
    value = os.environ.get(config.LAB_MODE_ENV_VAR)
    if value != config.LAB_MODE_REQUIRED:
        logger.error(
            'LAB_MODE invalid — refusing to run outside lab',
            extra={
                'check': 'lab_mode',
                'value': value,
                'required': config.LAB_MODE_REQUIRED
            }
        )
        sys.exit(1)


def _check_allowed_host() -> None:
    # Exit if configured server host is not in ALLOWED_HOSTS.
    host = config.SERVER_HOST
    if host not in config.ALLOWED_HOSTS:
        logger.error(
            'SERVER_HOST not permitted',
            extra={
                'check': 'allowed_host',
                'host': host,
                'allowed_hosts': config.ALLOWED_HOSTS
            }
        )
        sys.exit(1)


def _check_debugger() -> None:
    # Windows only — log a warning if a debugger is attached, but do not exit.
    if platform.system() != 'Windows':
        return

    try:
        import ctypes
        if ctypes.windll.kernel32.IsDebuggerPresent():
            logger.warning('debugger detected — proceeding in lab mode',
                           extra={'check': 'debugger'})
    except Exception as e:
        # Non-fatal — log and continue if the check itself fails
        logger.warning('debugger check failed', extra={'reason': str(e)})


def _check_vm() -> None:
    # Detect VBOX/VMware via registry (Windows) or DMI strings (Linux).
    # Logs INFO only — lab environment IS expected to be a VM.
    indicators = []

    if platform.system() == 'Windows':
        indicators = _check_vm_windows()
    elif platform.system() == 'Linux':
        indicators = _check_vm_linux()

    if indicators:
        logger.info(
            'VM environment detected',
            extra={
                'check': 'vm_detection',
                'indicators': indicators,
                'platform': platform.system()
            }
        )
    else:
        logger.info(
            'no VM indicators found',
            extra={
                'check': 'vm_detection',
                'platform': platform.system()
            }
        )


def _check_vm_windows() -> list:
    # Check Windows registry for VBOX/VMware strings, return list of found indicators.
    found = []
    try:
        import winreg
        vm_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Oracle\VirtualBox Guest Additions'),
            (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\VMware, Inc.\VMware Tools'),
            (winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\VBoxGuest'),
            (winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\vmhgfs'),
        ]
        for hive, key_path in vm_keys:
            try:
                winreg.OpenKey(hive, key_path)
                found.append(key_path.split('\\')[-1])
            except FileNotFoundError:
                pass
    except Exception as e:
        logger.warning('VM registry check failed', extra={'reason': str(e)})
    return found


def _check_vm_linux() -> list:
    # Check Linux DMI/system files for hypervisor strings.
    found = []
    dmi_paths = [
        '/sys/class/dmi/id/product_name',
        '/sys/class/dmi/id/sys_vendor',
        '/sys/class/dmi/id/board_vendor',
    ]
    vm_strings = ['virtualbox', 'vmware', 'qemu', 'kvm', 'xen', 'hyper-v']

    for path in dmi_paths:
        try:
            with open(path, 'r') as f:
                content = f.read().lower()
                for vm_str in vm_strings:
                    if vm_str in content and vm_str not in found:
                        found.append(vm_str)
        except (FileNotFoundError, PermissionError):
            pass

    return found


# Public API
def check_lab_environment() -> None:
    # Run all environment checks — exits on failure, logs and continues on warnings.
    _check_lab_mode()
    _check_allowed_host()
    _check_debugger()
    _check_vm()

    logger.info('environment checks passed', extra={'component': 'agent'})


# Self-test
if __name__ == '__main__':
    import subprocess

    print("Running environment_checks self-test...")

    # Test 1 — LAB_MODE not set causes sys.exit(1)
    result = subprocess.run(
        [sys.executable, '-c',
         'from agent.environment_checks import _check_lab_mode; _check_lab_mode()'],
        capture_output=True, text=True,
        env={**os.environ, 'LAB_MODE': '0'},  # explicitly wrong value
    )
    assert result.returncode == 1, \
        "FAIL: process should exit with code 1 when LAB_MODE != '1'"
    print("  [OK] LAB_MODE=0 causes sys.exit(1)")

    # Test 2 — LAB_MODE unset causes sys.exit(1)
    env_without_lab = {k: v for k, v in os.environ.items() if k != 'LAB_MODE'}
    result = subprocess.run(
        [sys.executable, '-c',
         'from agent.environment_checks import _check_lab_mode; _check_lab_mode()'],
        capture_output=True, text=True,
        env=env_without_lab,
    )
    assert result.returncode == 1, \
        "FAIL: process should exit with code 1 when LAB_MODE is unset"
    print("  [OK] LAB_MODE unset causes sys.exit(1)")

    # Test 3 — LAB_MODE=1 does not exit
    result = subprocess.run(
        [sys.executable, '-c',
         'from agent.environment_checks import _check_lab_mode; _check_lab_mode(); print("passed")'],
        capture_output=True, text=True,
        env={**os.environ, 'LAB_MODE': '1'},
    )
    assert result.returncode == 0,   "FAIL: LAB_MODE=1 should not cause exit"
    assert 'passed' in result.stdout,"FAIL: function should return normally with LAB_MODE=1"
    print("  [OK] LAB_MODE=1 passes without exit")

    # Test 4 — SERVER_HOST not in ALLOWED_HOSTS causes sys.exit(1)
    result = subprocess.run(
        [sys.executable, '-c',
         '''
import sys
sys.path.insert(0, ".")
from common import config
config.SERVER_HOST   = "evil.attacker.com"
config.ALLOWED_HOSTS = ["c2.lab.internal", "192.168.100.10"]
from agent.environment_checks import _check_allowed_host
_check_allowed_host()
'''],
        capture_output=True, text=True,
        env={**os.environ, 'LAB_MODE': '1'},
    )
    assert result.returncode == 1, \
        "FAIL: process should exit when SERVER_HOST not in ALLOWED_HOSTS"
    print("  [OK] SERVER_HOST not in ALLOWED_HOSTS causes sys.exit(1)")

    # Test 5 — VM detection does not exit
    result = subprocess.run(
        [sys.executable, '-c',
         'from agent.environment_checks import _check_vm; _check_vm(); print("passed")'],
        capture_output=True, text=True,
        env={**os.environ, 'LAB_MODE': '1'},
    )
    assert result.returncode == 0,   "FAIL: VM detection should never cause exit"
    assert 'passed' in result.stdout,"FAIL: VM detection should return normally"
    print("  [OK] VM detection logs and continues without exit")

    # Test 6 — Debugger check does not exit
    result = subprocess.run(
        [sys.executable, '-c',
         'from agent.environment_checks import _check_debugger; _check_debugger(); print("passed")'],
        capture_output=True, text=True,
        env={**os.environ, 'LAB_MODE': '1'},
    )
    assert result.returncode == 0,   "FAIL: debugger check should never cause exit"
    assert 'passed' in result.stdout,"FAIL: debugger check should return normally"
    print("  [OK] debugger check logs and continues without exit")

    print("\nAll environment_checks self-tests passed.")