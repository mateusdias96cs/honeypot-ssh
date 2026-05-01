import logging
import random
from typing import List, Dict
from datetime import datetime, timedelta
import time

class DeceptionEngine:
    """Simulador de processos, logs, atividades do sistema"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.boot_time = self.calculate_boot_time()
        self.processes = self._generate_processes()
    
    def calculate_boot_time(self) -> datetime:
        """Fazer com que pareça realista o tempo de boot"""
        days_ago = random.randint(30,200)
        return datetime.now() - timedelta(days=days_ago)

    def _generate_processes(self) -> List[Dict]:
        processes = [
            {'user': 'root', 'pid': 1, 'cmd': '/sbin/init splash'},
            {'user': 'root', 'pid': 123, 'cmd': '/lib/systemd/systemd-journald'},
            {'user': 'root', 'pid': 234, 'cmd': '/lib/systemd/systemd-udevd'},
            {'user': 'syslog', 'pid': 345, 'cmd': '/usr/sbin/rsyslogd'},
            {'user': 'root', 'pid': 456, 'cmd': '/usr/sbin/sshd -D [listener]'},
            {'user': 'postgres', 'pid': 567, 'cmd': '/usr/lib/postgresql/12/bin/postgres'},
            {'user': 'root', 'pid': 830, 'cmd': '/usr/sbin/cron -f'},
            {'user': 'ntp', 'pid': 845, 'cmd': '/usr/sbin/ntpd -p /var/run/ntpd.pid -g -u 111:115'},
            {'user': 'root', 'pid': 900, 'cmd': '/sbin/dhclient -1 -v -pf /run/dhclient.eth0.pid'},
            {'user': 'root', 'pid': 1050, 'cmd': '/usr/sbin/irqbalance --foreground'},
            {'user': 'www-data', 'pid': 1200, 'cmd': 'nginx: master process /usr/sbin/nginx'},
            {'user': 'redis', 'pid': 1350, 'cmd': '/usr/bin/redis-server 127.0.0.1:6379'},

        ]
        random.shuffle(processes)
        return processes
    
    def _cmd_migrate(self, args: list) -> str:
        if not args:
            return "Usage: migrate <pid>"
        
        pid = args[0]

        for process in self.processes:
            if str(process['pid']) == pid:
                old_cmd = process['cmd']
                process['cmd'] = '[migrated]'
                time.sleep(2)
                return f"base: migrate:command not found"
            return "bash: migrate: command not found"
    
    def _generate_bash_history(self) -> str:
        commands = [
            'cd /home/PC'
            'ls -la',
            'cat /etc/hostname',
            'sudo apt update',
            'python script.py',
            'git status',
            'ssh user@server.com',
            'nano config.txt',
            'make build',
            'docker ps',
            'curl https://api.example.com',
            'grep -r "todo" .',
            'find . -name "*.log"',
            'df -h',
            'top -b -n 1 | head -20',
        ]
        sampled = random.sample(commands, len(commands))
        content_formatted = '\n'.join(sampled)
        return content_formatted

    def get_uptime(self) -> str:
        """Retorna uptime em formato linux"""
        uptime_seconds = int((datetime.now() - self.boot_time).total_seconds())
        days = uptime_seconds // 86400
        hours = (uptime_seconds % 86400) // 3600
        mins = (uptime_seconds % 3600) // 60
        return f"{days} day(s), {hours}:{mins:02d}"
    
    def get_ps_output(self, user_cmd: str = None) -> str:
        """Retorna ps aux"""
        header = "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
        lines = [header]

        for proc in self.processes:
            line = f"{proc['user']:<10}{proc['pid']:<4} 0.0  0.1  12345  1234 ?        Ss   10:00   0:00{proc['cmd']}"
            lines.append(line)

        # Adicionar comando ps aux
        if user_cmd:
            lines.append(f"PC{random.randint(5000, 9999)} 0.0  0.0  34892  3892 pts/0    R+   10:20   0:00{user_cmd}")

        return '\n'.join(lines)
    
    def get_randomized_response_delay(self) -> float:
        generate_number = random.uniform(0.05, 1.5)
        time.sleep(3)

    def get_permission_denied_message(self) -> str:
        """Retornar mensagem de acesso negado (variada)"""
        messages = [
            "Permission denied",
            "Access denied",
            "Operation not permitted",
            "You don't have permission to access this resource"
        ]
        return random.choice(messages)

    def get_command_not_found_message(self, cmd: str) -> str:
        """Retornar mensagem de comando não encontrado"""
        messages = [
            f"-bash:{cmd}: command not found",
            f"bash:{cmd}: command not found",
            f"sh:{cmd}: not found",
            f"zsh: command not found:{cmd}"
        ]
        return random.choice(messages)