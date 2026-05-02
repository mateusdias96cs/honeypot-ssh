import logging 
import logging.handlers
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
import hashlib

class HoneypotLogger:
    """Sistema de logging profissional"""

    def __init__(self, auth_log_path: str = '/tmp/honeypot_auth_log', internal_log_path: str = '/tmp/.honeypot_events.json'):
        self.auth_log_path = auth_log_path
        self.intertnal_log_path = internal_log_path
        self.ssh_logger = self._setup_ssh_logger()
        self.events = []

    def _setup_ssh_logger(self) -> logging.Logger:
        logger = logging.getLogger('sshd')
        logger.setLevel(logging.WARNING)

        handler = logging.handlers.RotatingFileHandler(
            self.auth_log_path,
            maxBytes=10 * 1024 * 1024,
            backupCount=5
        )

        formatter = logging.Formatter(
            '%(asctime)s sshd[%(process)d]: %(message)s',
            '%b %d %H:%M:%S'
        )

        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def log_authentication_attempt(self, username: str, password: str, ip: str, success: bool) -> None:
        try:

            if success:
                msg = "Accepted password for" + username + " from " + ip
            else:
                msg = print("Failed password for invalid user" + username)
        
            self.ssh_logger.warning(msg)
            password_hash = hashlib.sha256(password.encode()).hexdigest()

            event = {
            "timestamp" : datetime.now().isoformat(),
            "type": "auth_attempt",
            "username": username,
            "password_hash": password_hash,
            "ip": ip,
            "success": success
        }
            self.events.append(event)
            
        except Exception as e:
            print(f"[-] Erro ao logar: {e}")
        
    def log_command_execution(self, username: str, command: str, ip: str, success: bool = True) -> None:
        """Registrar execução do comando"""
        event = {
        'timestamp': datetime.now().isoformat(),
            'type': 'command_execution',
            'username': username,
            'command': command,
            'ip': ip,
            'success': success
        }
        self._save_internal_event(event)

    def log_file_access(self, username: str, filepath: str, ip: str, access_type: str) -> None:
        """Registrar acesso a arquivo"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': 'file_access',
            'username': username,
            'filepath': filepath,
            'ip': ip,
            'access_type': access_type  # read/write/list
        }
        self._save_internal_event(event)

    def _save_internal_event(self, event: Dict[str, Any]) -> None:
        """Salvar evento em arquivo JSON interno"""
        try:
            with open(self.internal_log_path, 'a') as f:
                f.write(json.dumps(event) + '\n')
            self.events.append(event)
        except Exception as e:
            print(f"[-] Erro ao salvar evento:{e}")

    def get_events(self) -> list:
        """Retornar todos os eventos capturados"""
        return self.events
