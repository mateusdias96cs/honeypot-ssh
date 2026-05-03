import logging 
from typing import Optional, Dict
from datetime import datetime
import time

class ShellSimulator:
    """Simula um shell bash/sh processa comando digitados pelo atacante"""
    def __init__(self, username: str, home_dir: str, filesystem=None,
                 honey_logger=None, client_ip: str = None):
        self.logger = logging.getLogger(__name__)
        self.username = username
        self.home_dir = home_dir
        self.current_dir = home_dir
        self.environment = self._setup_environment()
        self.command_history = []
        self.filesystem = filesystem
        self.honey_logger = honey_logger
        self.client_ip = client_ip
        self.sudo_attempts = 0

    def _setup_environment(self) -> Dict[str, str]:
        """Setup de variáveis de ambiente"""
        return {
            'USER': self.username,
            'HOME': self.home_dir,
            'SHELL': '/bin/bash',
            'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        }
    
    def execute_command(self, cmd: str) -> Optional[str]:
        try:
            self.command_history.append(cmd)

            parts = cmd.strip().split()
            if not parts:
                return ""
            command = parts[0]
            args = parts[1:]

            # Log command execution to HoneypotLogger
            if self.honey_logger and self.client_ip:
                self.honey_logger.log_command_execution(
                    self.username, cmd, self.client_ip
                )

            match command:
                case "ls":
                    return self._cmd_ls(args)
                case "pwd":
                    return self._cmd_pwd()
                case "whoami":
                    return self._cmd_whoami()
                case "id":
                    return self._cmd_id()
                case "uname":
                    return self._cmd_uname(args)
                case "hostname":
                    return self._cmd_hostname()
                case "date":
                    return self._cmd_date()
                case "echo":
                    return self._cmd_echo(args)
                case "cat":
                    return self._cmd_cat(args)
                case "sudo":
                    return self._cmd_sudo(args)
                case "wget":
                    return self._cmd_wget(args)
                case "curl":
                    return self._cmd_curl(args)
                case "history":
                    return self._cmd_history()
                case "cd":
                    return self._cmd_cd(args)
                case "ps":
                    return self._cmd_ps(args)
                case "ip":
                    return self._cmd_ip(args)
                case "ifconfig":
                    return self._cmd_ifconfig()
                case "netstat":
                    return self._cmd_netstat(args)
                case "find":
                    return self._cmd_find(args)
                case "ss":
                    return self._cmd_netstat(args)
                case "env":
                    return self._cmd_env()
                case "export":
                    return ""
                case "which":
                    return self._cmd_which(args)
                case "python" | "python3":
                    return self._cmd_python()
                case "nc" | "netcat":
                    return self._cmd_nc(args)
                case "ssh":
                    return self._cmd_ssh(args)
                case _:
                    return f"bash: {command}: command not found"
                
        except Exception as e:
            self.logger.error(f"[-] Erro ao executar comando:{e}")
            return f"[-] Erro: {e}"
    
    def _cmd_ls(self, args: list = None) -> str:
        target_dir = self.current_dir

        # se passou um path como argumento
        if args:
            non_flag_args = [a for a in args if not a.startswith('-')]
            if non_flag_args:
                path = non_flag_args[0]
                if self.filesystem:
                    target_dir = self.filesystem.normalize_path(self.current_dir, path)
                else:
                    if not path.startswith('/'):
                        path = self.current_dir.rstrip('/') + '/' + path
                    target_dir = path

        if self.filesystem:
            contents = self.filesystem.list_directory(target_dir)
            if contents is not None:
                if args and ('-la' in args or '-al' in args or '-l' in args):
                    lines = []
                    lines.append(f"total {len(contents) * 4}")
                    lines.append(f"drwxr-xr-x  {len(contents)} {self.username} {self.username} 4096 Apr 25 10:02 .")
                    lines.append(f"drwxr-xr-x  3 root root 4096 Apr 20 09:00 ..")
                    for item in contents:
                        item_path = target_dir.rstrip('/') + '/' + item
                        info = self.filesystem.get_file(item_path) or {}
                        perms = info.get('perms', '-rw-r--r--')
                        owner = info.get('owner', self.username)
                        tipo = info.get('tipo', 'file')
                        size = '4096' if tipo == 'dir' else '1024'
                        lines.append(f"{perms}  1 {owner} {owner} {size} Apr 25 10:02 {item}")
                    return '\n'.join(lines)
                return '  '.join(contents)

        if args and ('-la' in args or '-al' in args):
            return "drwxr-xr-x 5 PC PC 4096 Mar 10 12:34 ."
        return "Documents  Downloads  .bash_history  .ssh  secret_vault"
    
    def _cmd_pwd(self) -> str:
        return self.current_dir
    
    def _cmd_whoami(self) -> str:
        return self.username
    
    def _cmd_id(self) -> str:
        return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),27(sudo)"
     
    def _cmd_uname(self, args: list = None) -> str:
        if args and '-a' in args:
            return 'Linux webserver01 5.15.0-84-generic #93-Ubuntu SMP Tue Aug 29 14:25:21 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux'
        if args and '-r' in args:
            return '5.15.0-84-generic'
        if args and '-m' in args:
            return 'x86_64'
        return 'Linux'
    
    def _cmd_hostname(self) -> str:
        return 'webserver01'
    
    def _cmd_date(self) -> str:
        return datetime.now().strftime('%a %b %d %H:%M:%S UTC %Y')
    
    def _cmd_echo(self, args: list) -> str:
        return ' '.join(args) if args else ''
    
    def _cmd_cat(self, args: list) -> str:
        if not args:
            return ""
        
        # handle flags like -n
        non_flag_args = [a for a in args if not a.startswith('-')]
        if not non_flag_args:
            return ""
        
        filepath = non_flag_args[0]

        # resolve relative path
        if self.filesystem:
            filepath = self.filesystem.normalize_path(self.current_dir, filepath)
        else:
            if not filepath.startswith('/'):
                filepath = self.current_dir.rstrip('/') + '/' + filepath

        # Log file access to HoneypotLogger
        if self.honey_logger and self.client_ip:
            self.honey_logger.log_file_access(
                self.username, filepath, self.client_ip, 'read'
            )

        # special virtual files
        if filepath == '/proc/version':
            return 'Linux version 5.15.0-84-generic (buildd@ubuntu) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #93-Ubuntu SMP Tue Aug 29 14:25:21 UTC 2023'
        
        if filepath == '/proc/cpuinfo':
            return 'processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel Xeon E5-2680 v4 @ 2.40GHz\ncpu MHz\t\t: 2400.000\ncache size\t: 35840 KB'

        if self.filesystem:
            content = self.filesystem.read_file(filepath)
            if content:
                return content
        return f"cat: {filepath}: No such file or directory"

    def _cmd_sudo(self, args: list) -> str:
        if self.sudo_attempts >= 3:
            return f"sudo: 3 incorrect password attempts"
        self.sudo_attempts += 1
        if self.sudo_attempts >= 3:
            return f"[sudo] password for {self.username}: \nSorry, try again.\n[sudo] password for {self.username}: \nSorry, try again.\n[sudo] password for {self.username}: \nsudo: 3 incorrect password attempts"
        return f"[sudo] password for {self.username}: \nSorry, try again."

    def _cmd_ps(self, args: list = None) -> str:
        header = "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
        processes = [
            header,
            "root           1  0.0  0.1  19232  3088 ?        Ss   Apr20   0:02 /sbin/init splash",
            "root         123  0.0  0.1  25888  4432 ?        Ss   Apr20   0:00 /lib/systemd/systemd-journald",
            "root         234  0.0  0.1  29904  5388 ?        Ss   Apr20   0:00 /lib/systemd/systemd-udevd",
            "root         456  0.0  0.1  72296  5948 ?        Ss   Apr20   0:00 /usr/sbin/sshd -D",
            "www-data    1200  0.0  0.2 197456 18432 ?        Ss   Apr20   0:00 nginx: master process /usr/sbin/nginx",
            "www-data    1201  0.1  0.3 197456 24576 ?        S    Apr20   0:12 nginx: worker process",
            "postgres    1350  0.0  0.5 213456 43520 ?        Ss   Apr20   0:05 /usr/lib/postgresql/12/bin/postgres",
            "redis       1420  0.1  0.2  65432 18234 ?        Ssl  Apr20   1:23 /usr/bin/redis-server 127.0.0.1:6379",
            "root        1600  0.0  0.1  14432  2048 ?        Ss   Apr20   0:00 /usr/sbin/cron -f",
            f"{self.username}    2234  0.0  0.1  23456  5432 pts/0    Ss   10:15   0:00 -bash",
            f"{self.username}    2289  0.0  0.0  34892  3892 pts/0    R+   10:20   0:00 ps aux",
        ]
        return '\n'.join(processes)

    def _cmd_ip(self, args: list = None) -> str:
        if not args or args[0] in ('a', 'addr', 'address'):
            return (
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
                "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
                "    inet 127.0.0.1/8 scope host lo\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n"
                "    link/ether 08:00:27:ab:cd:ef brd ff:ff:ff:ff:ff:ff\n"
                "    inet 192.168.1.10/24 brd 192.168.1.255 scope global dynamic eth0\n"
                "    inet6 fe80::a00:27ff:feab:cdef/64 scope link"
            )
        if args[0] == 'route':
            return (
                "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n"
                "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.10"
            )
        return ""

    def _cmd_ifconfig(self) -> str:
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 192.168.1.10  netmask 255.255.255.0  broadcast 192.168.1.255\n"
            "        inet6 fe80::a00:27ff:feab:cdef  prefixlen 64  scopeid 0x20<link>\n"
            "        ether 08:00:27:ab:cd:ef  txqueuelen 1000  (Ethernet)\n"
            "        RX packets 123456  bytes 98765432 (98.7 MB)\n"
            "        TX packets 45678  bytes 12345678 (12.3 MB)\n\n"
            "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
            "        inet 127.0.0.1  netmask 255.0.0.0\n"
            "        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n"
            "        loop  txqueuelen 1000  (Local Loopback)"
        )

    def _cmd_netstat(self, args: list = None) -> str:
        return (
            "Active Internet connections (only servers)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      456/sshd\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1200/nginx\n"
            "tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      1200/nginx\n"
            "tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      1350/postgres\n"
            "tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN      1420/redis-server\n"
            "tcp        0      0 0.0.0.0:2222            0.0.0.0:*               LISTEN      2100/sshd"
        )

    def _cmd_find(self, args: list = None) -> str:
        if not args:
            return "find: missing argument"

        raw = args[0] if args else self.current_dir
        name_filter = None

        if '-name' in args:
            idx = args.index('-name')
            if idx + 1 < len(args):
                name_filter = args[idx + 1].replace('*', '').replace('"', '').replace("'", '')

        if self.filesystem:
            # Expand ~ and normalize relative paths to absolute before resolving
            if raw == '~':
                raw = self.home_dir
            abs_path = self.filesystem.normalize_path(self.current_dir, raw)
            resolved = self.filesystem.resolve_path(abs_path)
            results = []
            for path in self.filesystem.fs_tree.keys():
                if path.startswith(resolved):
                    if name_filter is None or name_filter in path:
                        results.append(path)
            return '\n'.join(results) if results else ""

        return ""

    def _cmd_env(self) -> str:
        lines = []
        for k, v in self.environment.items():
            lines.append(f"{k}={v}")
        lines.append("LANG=en_US.UTF-8")
        lines.append("TERM=xterm-256color")
        lines.append(f"LOGNAME={self.username}")
        return '\n'.join(lines)

    def _cmd_which(self, args: list) -> str:
        if not args:
            return ""
        cmd = args[0]
        known = {
            'python3': '/usr/bin/python3',
            'python': '/usr/bin/python3',
            'bash': '/bin/bash',
            'sh': '/bin/sh',
            'cat': '/bin/cat',
            'ls': '/bin/ls',
            'find': '/usr/bin/find',
            'wget': '/usr/bin/wget',
            'curl': '/usr/bin/curl',
            'sudo': '/usr/bin/sudo',
            'ssh': '/usr/bin/ssh',
            'nc': '/usr/bin/nc',
            'netcat': '/usr/bin/netcat',
        }
        return known.get(cmd, f"which: no {cmd} in ({self.environment.get('PATH', '')})")

    def _cmd_python(self) -> str:
        return "Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux\nType \"help\", \"copyright\", \"credits\" or \"license\" for more information.\n>>>"

    def _cmd_nc(self, args: list) -> str:
        time.sleep(3)
        return "nc: connect to host: Connection refused"

    def _cmd_ssh(self, args: list) -> str:
        if not args:
            return "usage: ssh [-p port] [user@]hostname [command]"
        target = args[-1]
        time.sleep(4)
        host = target.split('@')[-1] if '@' in target else target
        return f"ssh: connect to host {host} port 22: Connection timed out"

    def get_prompt(self) -> str:
        if self.current_dir == self.home_dir:
            display = '~'
        elif self.current_dir.startswith(self.home_dir):
            display = '~' + self.current_dir[len(self.home_dir):]
        else:
            display = self.current_dir
        return f"{self.username}@webserver01:{display}$ "
    
    def _cmd_wget(self, args: list) -> str:
        target = args[0] if args else 'example.com'
        time.sleep(3)
        host = target.replace('http://', '').replace('https://', '').split('/')[0]
        return (
            f"--{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}--  {target}\n"
            f"Resolving {host} ({host})... failed: Name or service not known.\n"
            f"wget: unable to resolve host address '{host}'"
        )

    def _cmd_curl(self, args: list) -> str:
        target = args[-1] if args else 'example.com'
        time.sleep(2)
        host = target.replace('http://', '').replace('https://', '').split('/')[0]
        return f"curl: (6) Could not resolve host: {host}"

    def _cmd_history(self) -> str:
        return '\n'.join(f"  {i+1}  {cmd}" for i, cmd in enumerate(self.command_history))

    def _cmd_cd(self, args: list) -> str:
        if not args:
            self.current_dir = self.home_dir
            return ""
        
        target = args[0]
        
        # handle cd -
        if target == '-':
            return self.current_dir

        if self.filesystem:
            new_path = self.filesystem.normalize_path(self.current_dir, target)
        else:
            if target.startswith('/'):
                new_path = target
            else:
                new_path = self.current_dir.rstrip('/') + '/' + target
            # normalize path (handle .. and .)
            parts = []
            for part in new_path.split('/'):
                if part == '..':
                    if parts:
                        parts.pop()
                elif part and part != '.':
                    parts.append(part)
            new_path = '/' + '/'.join(parts)

        if self.filesystem and self.filesystem.exists(new_path):
            file_info = self.filesystem.get_file(new_path)
            if file_info and file_info.get('tipo') != 'dir':
                return f"bash: cd: {target}: Not a directory"
            if self.filesystem.is_locked(new_path):
                return (
                    f"Permission denied: {target} is encrypted.\n"
                    f"Access requires decryption key.\n"
                    f"Hash: $2b$14$XkJ9mNpQvRsWtYuZaAbBcDeFgHiJkLmNoPqRsTuVwXyZaAbBcDeFgH\n"
                    f"Hint: bcrypt rounds=14"
                )
            self.current_dir = new_path
            return ""
        return f"bash: cd: {target}: No such file or directory"