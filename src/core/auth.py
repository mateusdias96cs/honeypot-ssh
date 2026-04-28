import json
import hashlib
import logging
from typing import Dict, Optional, Tuple
from pathlib import Path

class AuthenticationManager:
    


    def __init__(self, users_file: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self.users: Dict[str, Dict] = {}
        self.users_file = users_file or "config/users.json"
        self.load_users()

    def load_users(self) -> None:
        path = Path(self.users_file)

        if path.exists():
            with open(path, "r") as f:
                self.users = json.load(f)
                
            self.logger.info(f"Sucesso: {len(self.users)} usuários carregados.")
        else:
            self.users = self._create_default_users()
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, 'w') as f:
                json.dump(self.users, f)
            self.logger.warning("Arquivo de usuários não encontrado. Usando lista padrão.")


    def _create_default_users(self) -> Dict[str, Dict]:
        """
        Criar usuários padrão realistas
        Cada um representa um cenário comum
        """
        return {
            'root': {
                'password': 'root@server2024',  # Senha "forte" mas comum
                'uid': 0,
                'gid': 0,
                'shell': '/bin/bash',
                'home': '/root',
                'real_name': 'root'
            },
            'admin': {
                'password': 'admin123',  # Senha fraca comum
                'uid': 1000,
                'gid': 1000,
                'shell': '/bin/bash',
                'home': '/home/admin',
                'real_name': 'Administrator'
            },
            'carlos': {
                'password': 'carlos2022',  # Senha média
                'uid': 1001,
                'gid': 1001,
                'shell': '/bin/bash',
                'home': '/home/carlos',
                'real_name': 'Carlos User'
            },
            'postgres': {
                'password': 'postgres',  # Padrão de serviço
                'uid': 113,
                'gid': 120,
                'shell': '/bin/false',
                'home': '/var/lib/postgresql',
                'real_name': 'PostgreSQL'
            },
            'deploy': {
                'password': 'deploy_key_2024',  # Chave de deploy
                'uid': 1002,
                'gid': 1002,
                'shell': '/bin/bash',
                'home': '/home/deploy',
                'real_name': 'Deploy User'
            },
            'jenkins': {
                'password': 'jenkins_ci_secret',
                'uid': 114,
                'gid': 125,
                'shell': '/bin/false',
                'home': '/var/lib/jenkins',
                'real_name': 'Jenkins'
            },
        }
            

