import os
from pathlib import Path
from typing import Dict, Any

# Carregar .env se existir
env_file = Path(__file__).parent.parent / '.env'
if env_file.exists():
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ.setdefault(key.strip(), value.strip())

def load_configuration() -> Dict[str, Any]:
    try:
        config = {
            'host': os.getenv('SSH_HOST', '0.0.0.0'),
            'port': int(os.getenv('SSH_PORT', '2222')),
            'banner': os.getenv('SSH_BANNER', 'SSH-2.0-OpenSSH_8.2p1'),
            'log_file': os.getenv('LOG_FILE', '/tmp/honeypot_auth.log'),
            'internal_log': os.getenv('INTERNAL_LOG', '/tmp/.honeypot_events.json'),
            'users_file': os.getenv('USERS_FILE', 'config/users.json'),
            'auth_timeout': int(os.getenv('AUTH_TIMEOUT', '10')),
            'max_threads': int(os.getenv('MAX_THREADS', '50')),
            'enable_logging': os.getenv('ENABLE_LOGGING', 'true').lower() == 'true',
            'debug_mode': os.getenv('DEBUG_MODE', 'false').lower() == 'true',
        }
        return config
    except Exception as e:
        print(f"[-] Erro ao carregar configuração: {e}")
        return get_default_configuration()

def get_default_configuration() -> Dict[str, Any]:
    return {
        'host': '0.0.0.0',
        'port': 2222,
        'banner': 'SSH-2.0-OpenSSH_8.2p1',
        'log_file': '/tmp/honeypot_auth.log',
        'internal_log': '/tmp/.honeypot_events.json',
        'users_file': 'config/users.json',
        'auth_timeout': 10,
        'max_threads': 50,
        'enable_logging': True,
        'debug_mode': False,
    }

CONFIG = load_configuration()