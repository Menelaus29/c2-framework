"""
Exmaple of the config file used in the project. The actual config file is not 
committed to the repository for security reasons.
"""
# Network
ALLOWED_HOSTS = [
    'c2.lab.internal',
    '192.168.100.10',
]

SERVER_HOST  = 'c2.lab.internal'
SERVER_PORT  = 443
BACKEND_PORT = 8443

# TLS
TLS_CERT_PATH = 'certs/server.crt'

# Beacon timing
BEACON_INTERVAL_S = 30
JITTER_PCT        = 20


# Traffic padding
PADDING_MIN_BYTES = 0
PADDING_MAX_BYTES = 128

# Cryptography
# In the real config file, this should be a random 32-byte key
PRE_SHARED_KEY = b'REPLACE_WITH_REAL_32_BYTE_KEY!!!'  

# Logging
LOG_LEVEL        = 'INFO'
LOG_DIR          = 'logs'
LOG_MAX_BYTES    = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 3

# Security controls
BLOCKED_COMMANDS = [
    'reg',
    'schtasks',
    'at',
    'sc',
    'net use',
    'arp',
    'nmap',
    'whoami /priv',
    'net localgroup',
]

# Lab environment
LAB_MODE_ENV_VAR  = 'LAB_MODE'
LAB_MODE_REQUIRED = '1'

BEHIND_NGINX = False  # set True when Nginx handles TLS termination
