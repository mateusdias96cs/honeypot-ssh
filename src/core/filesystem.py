import logging 
from typing import Dict, Optional, List
from datetime import datetime

class VirtualFilesystem:
    """Simula um filesystem realista"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.fs_tree = self._create_filesystem()

    def _create_filesystem(self) -> Dict:
        return {
        # Root directories
        '/': {'tipo': 'dir', 'perms': 'drwxr-xr-x', 'owner': 'root'},
        '/home': {'tipo': 'dir', 'perms': 'drwxr-xr-x', 'owner': 'root'},
        '/etc': {'tipo': 'dir', 'perms': 'drwxr-xr-x', 'owner': 'root'},
        '/var': {'tipo': 'dir', 'perms': 'drwxr-xr-x', 'owner': 'root'},
        '/tmp': {'tipo': 'dir', 'perms': 'drwxrwxrwt', 'owner': 'root'},
        '/opt': {'tipo': 'dir', 'perms': 'drwxr-xr-x', 'owner': 'root'},
        '/usr': {'tipo': 'dir', 'perms': 'drwxr-xr-x', 'owner': 'root'},
        '/root': {'tipo': 'dir', 'perms': 'drwx------', 'owner': 'root'},

        # User home
        '/home/PC': {'tipo': 'dir', 'perms': 'drwxr-xr-x', 'owner': 'PC'},
        '/home/PC/Documents': {'tipo': 'dir', 'perms': 'drwxr-xr-x', 'owner': 'PC'},
        '/home/PC/Downloads': {'tipo': 'dir', 'perms': 'drwxr-xr-x', 'owner': 'PC'},
        '/home/PC/.ssh': {'tipo': 'dir', 'perms': 'drwx------', 'owner': 'PC'},
        '/home/PC/.config': {'tipo': 'dir', 'perms': 'drwxr-xr-x', 'owner': 'PC'},

        # Honeytoken — pasta valiosa com hash falsa
        '/home/PC/secret_vault': {
            'tipo': 'dir',
            'perms': 'drwx------',
            'owner': 'PC',
            'locked': True,
            'hash': '$2b$14$XkJ9mNpQvRsWtYuZaAbBcDeFgHiJkLmNoPqRsTuVwXyZaAbBcDeFgH',
        },

        # Files in home
        '/home/PC/.bash_history': {
            'tipo': 'file',
            'perms': '-rw-------',
            'owner': 'PC',
            'conteudo': 'cd /home/PC\nls -la\nssh admin@192.168.1.10\nsudo apt update\npython3 deploy.py\ngit pull origin main\ncat .env\nnano config.yaml\n'
        },
        '/home/PC/.bash_profile': {
            'tipo': 'file',
            'perms': '-rw-r--r--',
            'owner': 'PC',
            'conteudo': 'export PATH=$PATH:/usr/local/bin\nexport EDITOR=nano\n'
        },
        '/home/PC/.env': {
            'tipo': 'file',
            'perms': '-rw-------',
            'owner': 'PC',
            'conteudo': 'DB_HOST=localhost\nDB_PORT=5432\nDB_NAME=production_db\nDB_USER=PC\nDB_PASS=C@rl0s_Pr0d_2024!\nSECRET_KEY=sk_prod_xK9mNpQvRsWtYuZaAbBcDe\nAPI_URL=https://api.internal.company.com\n'
        },
        '/home/PC/Documents/notes.md': {
            'tipo': 'file',
            'perms': '-rw-r--r--',
            'owner': 'PC',
            'conteudo': '# Server Notes\n- DB backup runs every Sunday at 3am\n- SSH keys stored in secret_vault\n- Contact admin@company.com for access issues\n'
        },
        '/home/PC/Documents/budget_2024.xlsx': {
            'tipo': 'file',
            'perms': '-rw-r--r--',
            'owner': 'PC',
            'conteudo': '[binary file]'
        },
        '/home/PC/.ssh/known_hosts': {
            'tipo': 'file',
            'perms': '-rw-r--r--',
            'owner': 'PC',
            'conteudo': '192.168.1.10 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...\n192.168.1.20 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD...\n'
        },
        '/home/PC/.ssh/id_rsa.pub': {
            'tipo': 'file',
            'perms': '-rw-r--r--',
            'owner': 'PC',
            'conteudo': 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC9xK8mNpQvRsWtYu PC@webserver01\n'
        },

        # /etc files
        '/etc/passwd': {
            'tipo': 'file',
            'perms': '-rw-r--r--',
            'owner': 'root',
            'conteudo': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nPC:x:1001:1001:PC User:/home/PC:/bin/bash\npostgres:x:113:120:PostgreSQL:/var/lib/postgresql:/bin/false\njenkins:x:114:125:Jenkins:/var/lib/jenkins:/bin/false\ndeploy:x:1002:1002:Deploy User:/home/deploy:/bin/bash\n'
        },
        '/etc/hostname': {
            'tipo': 'file',
            'perms': '-rw-r--r--',
            'owner': 'root',
            'conteudo': 'webserver01\n'
        },
        '/etc/hosts': {
            'tipo': 'file',
            'perms': '-rw-r--r--',
            'owner': 'root',
            'conteudo': '127.0.0.1 localhost\n127.0.1.1 webserver01\n192.168.1.10 db-server\n192.168.1.20 backup-server\n192.168.1.30 monitoring\n'
        },
        '/etc/ssh': {'tipo': 'dir', 'perms': 'drwxr-xr-x', 'owner': 'root'},
        '/etc/ssh/sshd_config': {
            'tipo': 'file',
            'perms': '-rw-r--r--',
            'owner': 'root',
            'conteudo': 'Port 22\nPermitRootLogin no\nPasswordAuthentication yes\nX11Forwarding no\nMaxAuthTries 3\n'
        },
        '/etc/crontab': {
            'tipo': 'file',
            'perms': '-rw-r--r--',
            'owner': 'root',
            'conteudo': '0 3 * * 0 root /opt/backup/backup.sh\n0 * * * * PC /home/PC/scripts/monitor.py\n30 2 * * * root /usr/bin/apt-get update\n'
        },

        # /var
        '/var/log': {'tipo': 'dir', 'perms': 'drwxr-xr-x', 'owner': 'root'},
        '/var/log/auth.log': {
            'tipo': 'file',
            'perms': '-rw-r-----',
            'owner': 'root',
            'conteudo': 'Apr 24 10:02:01 webserver01 sshd[1234]: Accepted password for PC from 192.168.1.5\nApr 24 10:15:33 webserver01 sudo: PC : TTY=pts/0 ; COMMAND=/usr/bin/apt\nApr 24 11:42:10 webserver01 sshd[2341]: Failed password for root from 45.33.32.156\n'
        },
        '/var/log/syslog': {
            'tipo': 'file',
            'perms': '-rw-r-----',
            'owner': 'root',
            'conteudo': 'Apr 24 10:00:01 webserver01 systemd[1]: Started Daily apt download activities.\nApr 24 10:02:01 webserver01 CRON[1200]: (root) CMD (/opt/backup/backup.sh)\n'
        },
        '/var/www': {'tipo': 'dir', 'perms': 'drwxr-xr-x', 'owner': 'www-data'},
        '/var/www/html': {'tipo': 'dir', 'perms': 'drwxr-xr-x', 'owner': 'www-data'},
        '/var/www/html/index.php': {
            'tipo': 'file',
            'perms': '-rw-r--r--',
            'owner': 'www-data',
            'conteudo': '<?php\n// Company Internal Portal\nrequire_once "config.php";\nsession_start();\n?>\n'
        },
        '/var/www/html/config.php': {
            'tipo': 'file',
            'perms': '-rw-r--r--',
            'owner': 'www-data',
            'conteudo': '<?php\ndefine("DB_HOST", "localhost");\ndefine("DB_USER", "webapp");\ndefine("DB_PASS", "W3bApp_Pr0d!");\ndefine("DB_NAME", "company_portal");\n?>\n'
        },

        # /opt
        '/opt/backup': {'tipo': 'dir', 'perms': 'drwxr-xr-x', 'owner': 'root'},
        '/opt/backup/backup.sh': {
            'tipo': 'file',
            'perms': '-rwxr-xr-x',
            'owner': 'root',
            'conteudo': '#!/bin/bash\ntar -czf /var/backups/db_$(date +%Y%m%d).tar.gz /var/lib/postgresql\nscp /var/backups/*.tar.gz backup@192.168.1.20:/backups/\n'
        },
        '/opt/app': {'tipo': 'dir', 'perms': 'drwxr-xr-x', 'owner': 'PC'},
        '/opt/app/config.yaml': {
            'tipo': 'file',
            'perms': '-rw-r--r--',
            'owner': 'PC',
            'conteudo': 'database:\n  host: localhost\n  port: 5432\n  name: production_db\nredis:\n  host: 192.168.1.15\n  port: 6379\napi:\n  key: sk_prod_xK9mNpQvRsWtYuZaAbBcDe\n'
        },

        # /root
        '/root/.bash_history': {
            'tipo': 'file',
            'perms': '-rw-------',
            'owner': 'root',
            'conteudo': 'apt-get update\napt-get upgrade\nufw status\nnetstat -tulpn\ntail -f /var/log/auth.log\ncat /etc/shadow\n'
        },
        '/root/.ssh': {'tipo': 'dir', 'perms': 'drwx------', 'owner': 'root'},
        '/root/.ssh/authorized_keys': {
            'tipo': 'file',
            'perms': '-rw-------',
            'owner': 'root',
            'conteudo': 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC9xK8mNpQvRsWtYu admin@management-server\n'
        },
    }

    def exists(self, path: str) -> bool:
        """Verifica se um arquivo ou diretório existe"""
        return path in self.fs_tree

    def get_file(self, path: str) -> Optional[Dict]:
        """Obtém informações de um arquivo ou diretório"""
        if not self.exists(path):
            self.logger.warning(f"Caminho não encontrado: {path}")
            return None
        return self.fs_tree[path]

    def read_file(self, path: str) -> Optional[str]:
        """Lê o conteúdo de um arquivo"""
        file_info = self.get_file(path)
        if not file_info:
            return None
        
        if file_info.get('tipo') != 'file':
            self.logger.error(f"Caminho não é um arquivo: {path}")
            return None
        
        return file_info.get('conteudo', '')

    def list_directory(self, path: str) -> List[str]:
        """Lista o conteúdo de um diretório"""
        dir_info = self.get_file(path)
        if not dir_info:
            return []
        
        if dir_info.get('tipo') != 'dir':
            self.logger.error(f"Caminho não é um diretório: {path}")
            return []
        
        # Normalizar path para acabar com /
        if not path.endswith('/'):
            path += '/'
        
        # Encontrar todos os items que começam com este path
        contents = []
        for fs_path in self.fs_tree.keys():
            if fs_path.startswith(path) and fs_path != path.rstrip('/'):
                # Obter apenas o primeiro nível
                relative = fs_path[len(path):]
                if '/' not in relative or relative.endswith('/'):
                    if relative not in contents:
                        contents.append(relative.rstrip('/'))
        
        return sorted(contents)

    def get_permissions(self, path: str) -> Optional[str]:
        """Obtém as permissões de um arquivo/diretório"""
        file_info = self.get_file(path)
        if not file_info:
            return None
        return file_info.get('perms', '')

    def get_owner(self, path: str) -> Optional[str]:
        """Obtém o proprietário de um arquivo/diretório"""
        file_info = self.get_file(path)
        if not file_info:
            return None
        return file_info.get('owner', '')

    def is_locked(self, path: str) -> bool:
        """Verifica se um arquivo/diretório está bloqueado"""
        file_info = self.get_file(path)
        if not file_info:
            return False
        return file_info.get('locked', False)
