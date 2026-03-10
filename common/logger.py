import json
import logging
import logging.handlers
import os
from datetime import datetime, timezone, timedelta

from common import config

# Constants
_LOG_FORMAT_VERSION = '1'  # included in every log line for future parsing
_LOGGERS = {}               # module-level cache to avoid duplicate handlers
_TZ_UTC7 = timezone(timedelta(hours=7)) # timezone for logging

# JSON formatter
class _JsonFormatter(logging.Formatter):
    # Formats each log record as a single JSON line.

    def __init__(self, component: str, session_id: str = None):
        super().__init__()
        self._component  = component
        self._session_id = session_id

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            'timestamp':  datetime.now(_TZ_UTC7).isoformat(),
            'level':      record.levelname,
            'component':  self._component,
            'session_id': self._session_id,
            'message':    record.getMessage(),
        }

        # Merge any extra fields passed via the 'extra' kwarg
        for key, value in record.__dict__.items():
            if key not in _RESERVED_KEYS:
                entry[key] = value

        # Attach exception info if present
        if record.exc_info:
            entry['exception'] = self.formatException(record.exc_info)

        return json.dumps(entry)


# Keys that are part of the standard LogRecord — excluded from extra fields
_RESERVED_KEYS = {
    'name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
    'filename', 'module', 'exc_info', 'exc_text', 'stack_info',
    'lineno', 'funcName', 'created', 'msecs', 'relativeCreated',
    'thread', 'threadName', 'processName', 'process', 'message',
    'taskName',
}


# Public API
def get_logger(component: str, session_id: str = None) -> logging.Logger:
    # Return a cached JSON logger for the given component and optional session_id
    cache_key = f"{component}:{session_id}"
    if cache_key in _LOGGERS:
        return _LOGGERS[cache_key]

    logger = logging.getLogger(cache_key)
    logger.setLevel(getattr(logging, config.LOG_LEVEL.upper(), logging.INFO))

    # Avoid adding duplicate handlers if logger already has them
    if not logger.handlers:
        formatter = _JsonFormatter(component, session_id)

        # stdout handler
        stdout_handler = logging.StreamHandler()
        stdout_handler.setFormatter(formatter)
        logger.addHandler(stdout_handler)

        # rotating file handler
        os.makedirs(config.LOG_DIR, exist_ok=True)
        log_path = os.path.join(config.LOG_DIR, f"{component}.log")
        file_handler = logging.handlers.RotatingFileHandler(
            filename    = log_path,
            maxBytes    = config.LOG_MAX_BYTES,
            backupCount = config.LOG_BACKUP_COUNT,
            encoding    = 'utf-8',
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    # Prevent log records from propagating to the root logger
    logger.propagate = False

    _LOGGERS[cache_key] = logger
    return logger


def update_session(logger: logging.Logger, session_id: str) -> logging.Logger:
    # Return a new logger for the same component with an updated session_id
    # Extract component name from the cached key format 'component:session_id'
    component = logger.name.split(':')[0]
    return get_logger(component, session_id)