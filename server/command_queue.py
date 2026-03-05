import asyncio
import time
import uuid
import json
from dataclasses import dataclass, field
from enum import Enum

from common.logger import get_logger
from server.storage import Database

logger = get_logger('command_queue')


# TaskStatus enum
class TaskStatus(str, Enum):
    PENDING    = 'PENDING'
    DISPATCHED = 'DISPATCHED'
    COMPLETE   = 'COMPLETE'
    ERROR      = 'ERROR'


# Task dataclass
@dataclass
class Task:
    task_id:    str
    session_id: str
    command:    str
    args:       list
    timeout_s:  int
    queued_at:  float
    status:     TaskStatus = TaskStatus.PENDING


# CommandQueue
class CommandQueue:
    # Holds one asyncio.Queue per session and a flat task registry for lookups

    def __init__(self):
        self._queues: dict[str, asyncio.Queue] = {}
        self._tasks:  dict[str, Task]          = {}  # task_id -> Task for O(1) lookup
        self._lock = asyncio.Lock()

    def _get_or_create_queue(self, session_id: str) -> asyncio.Queue:
        # Return existing queue for session or create a new one
        if session_id not in self._queues:
            self._queues[session_id] = asyncio.Queue()
        return self._queues[session_id]

    async def enqueue_task(self, session_id: str, command: str, args: list,
                           timeout_s: int, db: Database) -> str:
        # Create a Task, add to session queue, persist to DB, return task_id
        task = Task(
            task_id    = str(uuid.uuid4()),
            session_id = session_id,
            command    = command,
            args       = args,
            timeout_s  = timeout_s,
            queued_at  = time.time(),
            status     = TaskStatus.PENDING,
        )

        async with self._lock:
            queue = self._get_or_create_queue(session_id)
            await queue.put(task)
            self._tasks[task.task_id] = task

        await db.insert_task(
            task_id    = task.task_id,
            session_id = session_id,
            command    = command,
            args       = json.dumps(args),  # store as JSON string in SQLite
            timeout_s  = timeout_s,
        )

        logger.info('task enqueued', extra={
            'session_id': session_id,
            'task_id':    task.task_id,
            'command':    command,
        })
        return task.task_id

    async def peek_task(self, session_id: str, db: Database = None) -> Task | None:
        async with self._lock:
            queue = self._queues.get(session_id)

            if queue and not queue.empty():
                for task in queue._queue:
                    if task.status == TaskStatus.PENDING:
                        return task

        if db is None:
            return None

        row = await db.get_pending_task(session_id)
        if row is None:
            return None

        task = Task(
            task_id=row["task_id"],
            session_id=row["session_id"],
            command=row["command"],
            args=json.loads(row["args"]),
            timeout_s=row["timeout_s"],
            queued_at=row["queued_at"],
            status=TaskStatus.PENDING,
        )

        async with self._lock:
            if task.task_id in self._tasks:
                return self._tasks[task.task_id]

            queue = self._get_or_create_queue(session_id)
            queue.put_nowait(task)
            self._tasks[task.task_id] = task

        logger.info(
            'task loaded from DB into queue',
            extra={'session_id': session_id, 'task_id': task.task_id, 'command': task.command},
        )

        return task

    async def mark_dispatched(self, task_id: str, db: Database) -> None:
        # Set task status to DISPATCHED in memory and in db
        async with self._lock:
            task = self._tasks.get(task_id)
            if task:
                task.status = TaskStatus.DISPATCHED

        await db.update_task_status(task_id, TaskStatus.DISPATCHED.value)
        logger.info('task dispatched', extra={'task_id': task_id})

    async def mark_complete(self, task_id: str, result: dict,
                            db: Database) -> None:
        # Set task status to COMPLETE, persist result to db
        async with self._lock:
            task = self._tasks.get(task_id)
            if task:
                task.status = TaskStatus.COMPLETE

        await db.update_task_status(task_id, TaskStatus.COMPLETE.value)
        await db.insert_result(
            result_id   = str(uuid.uuid4()),
            task_id     = task_id,
            stdout      = result.get('stdout', ''),
            stderr      = result.get('stderr', ''),
            exit_code   = result.get('exit_code', -1),
            duration_ms = result.get('duration_ms', 0),
        )
        logger.info('task complete', extra={
            'task_id':   task_id,
            'exit_code': result.get('exit_code'),
        })

    async def mark_error(self, task_id: str, db: Database) -> None:
        # Set task status to ERROR in memory and in db
        async with self._lock:
            task = self._tasks.get(task_id)
            if task:
                task.status = TaskStatus.ERROR

        await db.update_task_status(task_id, TaskStatus.ERROR.value)
        logger.warning('task error', extra={'task_id': task_id})

    async def get_tasks_for_session(self, session_id: str) -> list[Task]:
        # Return all in-memory tasks for a session ordered by queued_at
        async with self._lock:
            tasks = [t for t in self._tasks.values() if t.session_id == session_id]
        return sorted(tasks, key=lambda t: t.queued_at)


# Self-test
if __name__ == '__main__':
    import asyncio

    async def _test():
        print("Running command_queue self-test...")

        async with Database(':memory:') as db:
            cq  = CommandQueue()
            sid = 'test-session-id-001'

            # Insert a session row so FK constraints are satisfied
            await db.insert_session(sid, 'VICTIM-PC', 'jdoe', 'Windows 10', '1.0.0', 20)

            # enqueue_task
            tid = await cq.enqueue_task(sid, 'whoami', [], 30, db)
            assert tid, "FAIL: enqueue_task returned empty task_id"
            assert len(tid) == 36, "FAIL: task_id should be a UUID (36 chars)"
            print("  [OK] enqueue_task")

            # peek_task — should return the pending task
            task = await cq.peek_task(sid, db=db)
            assert task is not None,          "FAIL: peek_task returned None for non-empty queue"
            assert task.task_id   == tid,     "FAIL: peek_task returned wrong task"
            assert task.command   == 'whoami',"FAIL: command mismatch"
            assert task.status    == TaskStatus.PENDING, "FAIL: new task should be PENDING"
            print("  [OK] peek_task returns PENDING task")

            # peek_task is non-destructive — second peek returns same task
            task2 = await cq.peek_task(sid, db=db)
            assert task2 is not None,       "FAIL: second peek returned None"
            assert task2.task_id == tid,    "FAIL: second peek returned different task"
            print("  [OK] peek_task is non-destructive")

            # mark_dispatched
            await cq.mark_dispatched(tid, db)
            task = await cq.peek_task(sid, db=db)
            assert task is None, "FAIL: dispatched task should not appear as PENDING"
            db_row = await db.get_pending_task(sid)
            assert db_row is None, "FAIL: DB should show no PENDING tasks after dispatch"
            print("  [OK] mark_dispatched")

            # mark_complete
            result = {'stdout': 'VICTIM-PC\\jdoe', 'stderr': '', 'exit_code': 0, 'duration_ms': 42}
            await cq.mark_complete(tid, result, db)
            tasks = await cq.get_tasks_for_session(sid)
            assert tasks[0].status == TaskStatus.COMPLETE, "FAIL: task should be COMPLETE"
            results = await db.get_results_for_session(sid)
            assert len(results) == 1,                           "FAIL: expected 1 result in DB"
            assert results[0]['stdout'] == 'VICTIM-PC\\jdoe',   "FAIL: stdout mismatch in DB"
            print("  [OK] mark_complete")

            # get_tasks_for_session ordering — enqueue two more tasks
            tid2 = await cq.enqueue_task(sid, 'ipconfig', [], 30, db)
            tid3 = await cq.enqueue_task(sid, 'hostname', [], 30, db)
            tasks = await cq.get_tasks_for_session(sid)
            assert len(tasks) == 3, "FAIL: expected 3 tasks total"
            assert tasks[0].queued_at <= tasks[1].queued_at <= tasks[2].queued_at, \
                "FAIL: tasks not ordered by queued_at ascending"
            print("  [OK] get_tasks_for_session ordering")

            # peek_task returns None for unknown session
            none_task = await cq.peek_task('nonexistent-session', db=db)
            assert none_task is None, "FAIL: peek_task should return None for unknown session"
            print("  [OK] peek_task returns None for unknown session")

            # mark_error
            await cq.mark_error(tid2, db)
            tasks = await cq.get_tasks_for_session(sid)
            errored = next(t for t in tasks if t.task_id == tid2)
            assert errored.status == TaskStatus.ERROR, "FAIL: task should be ERROR"
            print("  [OK] mark_error")

        print("\nAll command_queue self-tests passed.")

    asyncio.run(_test())