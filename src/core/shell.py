import logging 
from typing import Optional, Dict
from datetime import datetime
import time

class ShellSimulator:
    """Simula um shell bash/sh processa comando digitados pelo atacante"""
    def __init__(self, username: str, home_dir: str, filesystem=None):
        self.logger = logging.getLogger(__name__)
        self.username = username
        self.home_dir = home_dir
        self.current_dir = home_dir
        self.environment = self._setup_environment()
        self.command_history = []
        self.filesystem = filesystem
        

    def _setup_environment(self) -> Dict[str, str]:
        """ Setup de variáveis de ambiente"""
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
            match command:
                case "ls":
                    return self._cmd_ls(args)
                case"pwd":
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
                case _:
                    return f"bash: {command}: command not found" 
                
        except Exception as e:
            self.logger.error(f"[-] Erro ao executar comando:{e}")
            return f"[-] Erro: {e}"
        
        
    def _cmd_ls(self, args: list = None) -> str:
        if self.filesystem:
            contents = self.filesystem.list_directory(self.current_dir)
            if contents:
                return ' '.join(contents)
            
        if args and ("-la" in args or "-al" in args):
            return "drwxr-xr-x 5 PC PC 4096 Mar 10 12:34"
                        
        return "Documents Downloads .bash_history .ssh"
    
    def _cmd_pwd(self) -> str:
        return self.current_dir
    
    def _cmd_whoami(self) -> str:
        return self.username
    
    def _cmd_id(self) -> str:
        return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username})"
     
    def _cmd_uname(self, args: list = None) -> str:
        if args and '-a' in args:
            return 'Linux webserver01 5.15.0-84-generic #93-Ubuntu SMP x86_64 x86_64 x86_64 GNU/Linux'
        return 'Linux'
    
    def _cmd_hostname(self) -> str:
        return 'webserver01'
    
    def _cmd_date(self) -> str:
        return datetime.now().strftime('%a %b%d %H:%M:%S %Z %Y')
    
    def _cmd_echo(self, args: list) -> str:
        return ''.join(args) if args else ''
    
    def _cmd_cat(self, args: list) -> str:
        if not args:
            return ""
        filename = args[0]
        files = {
            '/etc/hostname': 'webserver01\n',
            '/etc/os-release' : 'NAME="Ubuntu"\nVERSION="20.04"\n',
        }
        return files.get(filename, f'cat:{filename}: No such file or directory')

    def _cmd_sudo(self, args: list) -> str:
        return f'[sudo] password for{self.username}:'
    
    def get_prompt(self) -> str:
        return f"{self.username}@webserver01:~$ "
    
    def _cmd_find(self, args: list) -> str:
        if self.filesystem:
            return self.filesystem.list_directory(args[0])
        return "find: permission denied"

    def _cmd_wget(self, args: list) -> str:
    
        time.sleep(3)
        return "wget: unable to resolve host address"

    def _cmd_curl(self, args: list) -> str:    
        time.sleep(2)
        return "curl: (6) Could not resolve host"

    def _cmd_history(self) -> str:
        return '\n'.join(f"  {i+1}  {cmd}" for i, cmd in enumerate(self.command_history))


    def _cmd_cd(self, args: list) -> str:
        if not args:
            self.current_dir = self.home_dir
            return ""
        
        if args[0].startswith('/'):
            new_path = args[0]
        else:
            new_path = self.current_dir.rstrip('/') + '/' + args[0]

        if self.filesystem and self.filesystem.exists(new_path):

            if self.filesystem.is_locked(new_path):
                return(
                f"Permission denied: {args[0]} is encrypted.\n"
                f"Access requires decryption key.\n"
                f"Hash: $2b$14$XkJ9mNpQvRsWtYuZaAbBcDeFgHiJkLmNoPqRsTuVwXyZaAbBcDeFgH\n"
                f"Hint: bcrypt rounds=14"
                )
            self.current_dir = new_path
            return ""
        return f"bash: cd: {args[0]}: No such file or directory"
