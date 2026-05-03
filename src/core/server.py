import paramiko
import os
import time
import logging
import threading
import socket
from datetime import datetime
from pathlib import Path
from typing import Dict, Tuple, Optional
from collections import defaultdict
from dotenv import load_dotenv

load_dotenv()


class SSHServerInterface(paramiko.ServerInterface):
    """
    Implementação do servidor SSH com Paramiko.
    Autentica contra o auth.py e registra tentativas.
    """
    
    def __init__(self, auth_manager, honey_logger, threat_intel, logger, rate_limiter):
        super().__init__()
        self.auth_manager = auth_manager
        self.honey_logger = honey_logger
        self.threat_intel = threat_intel
        self.logger = logger
        self.rate_limiter = rate_limiter
        self.client_ip = None
        self.username = None
        self.authenticated = False
    
    def check_auth_password(self, username: str, password: str) -> int:
        """
        Autentica usuário com PASSWORD contra bcrypt real.
        Retorna paramiko.AUTH_SUCCESSFUL ou paramiko.AUTH_FAILED
        """
        self.username = username
        
        # Autenticar REAL contra auth.py
        success, user = self.auth_manager.authenticate(username, password)
        
        # Log a tentativa
        if self.honey_logger:
            self.honey_logger.log_authentication_attempt(
                username, password, self.client_ip, success=success
            )
        
        if success:
            self.authenticated = True
            self.logger.info(f"[✓] Autenticação bem-sucedida: {username}@{self.client_ip}")
            return paramiko.AUTH_SUCCESSFUL
        else:
            self.logger.warning(f"[✗] Falha de autenticação: {username}@{self.client_ip}")
            return paramiko.AUTH_FAILED
    
    def get_allowed_auths(self, username: str) -> str:
        """Retorna métodos de autenticação suportados"""
        return "password"
    
    def check_channel_request(self, kind: str, chanid: int) -> int:
        """Aceita requisições de canal SSH"""
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class SSHHoneypotServer:
    """
    Servidor SSH Honeypot funcional com Paramiko.
    """
    
    def __init__(self, components: Dict):
        self.auth_manager = components.get('auth')
        self.honey_logger = components.get('logger')
        self.threat_intel = components.get('threat_intel')
        self.rate_limiter = components.get('rate_limiter')
        
        self.logger = logging.getLogger(__name__)
        
        # Configurações SSH
        self.host = os.getenv('SSH_HOST', '0.0.0.0')
        self.port = int(os.getenv('SSH_PORT', 2222))
        
        # Gerar chave RSA (usar arquivo persistente em produção)
        self.host_key = self._get_or_create_host_key()
        
        self.server_socket = None
        self.running = False
    
    def _get_or_create_host_key(self) -> paramiko.RSAKey:
        """
        Obtém chave do servidor ou cria uma nova.
        Em produção, salvar em arquivo seguro.
        """
        key_file = Path("data/host_key.pem")
        
        try:
            if key_file.exists():
                return paramiko.RSAKey.from_private_key_file(str(key_file))
            else:
                key_file.parent.mkdir(parents=True, exist_ok=True)
                key = paramiko.RSAKey.generate(2048)
                key.write_private_key_file(str(key_file))
                os.chmod(key_file, 0o600)
                self.logger.info(f"[+] Chave SSH gerada: {key_file}")
                return key
        except Exception as e:
            self.logger.error(f"Erro ao carregar chave: {e}")
            # Usar chave em memória se falhar
            return paramiko.RSAKey.generate(2048)
    
    def start(self):
        """Inicia o servidor SSH"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(100)
            self.running = True
            
            self.logger.info(f"[+] Servidor SSH iniciado em {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    client_ip = client_address[0]
                    
                    # VERIFICAR RATE LIMIT
                    if self.rate_limiter and not self.rate_limiter.is_allowed(client_ip):
                        self.logger.warning(f"[!] Rate limit excedido: {client_ip}")
                        client_socket.close()
                        continue
                    
                    # VERIFICAR THREAT INTEL
                    if self.threat_intel:
                        reputation = self.threat_intel.check_ip_reputation(client_ip)
                        if reputation.get('threat_level', 0) >= 8:
                            self.logger.warning(f"[!] IP bloqueado (ameaça): {client_ip}")
                            client_socket.close()
                            continue
                    
                    # Iniciar thread para cliente
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_ip),
                        daemon=True
                    )
                    client_thread.start()
                
                except KeyboardInterrupt:
                    self.running = False
                    break
                except Exception as e:
                    self.logger.error(f"Erro ao aceitar conexão: {e}")
        
        except Exception as e:
            self.logger.error(f"Erro ao iniciar servidor: {e}")
        
        finally:
            self.stop()
    
    def _handle_client(self, client_socket: socket.socket, client_ip: str):
        """
        Trata conexão de cliente individual.
        Estabelece transporte SSH e aguarda autenticação.
        """
        transport = None
        
        try:
            # Criar transporte SSH
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(self.host_key)
            
            # Criar interface do servidor
            server_interface = SSHServerInterface(
                self.auth_manager,
                self.honey_logger,
                self.threat_intel,
                self.logger,
                self.rate_limiter
            )
            server_interface.client_ip = client_ip
            
            # Iniciar transporte
            transport.start_server(server=server_interface)
            
            # Aguardar autenticação (timeout 60s)
            channel = transport.accept(60)
            
            if channel is None:
                self.logger.warning(f"[!] Cliente não autenticado: {client_ip}")
                return
            
            if not server_interface.authenticated:
                self.logger.warning(f"[!] Autenticação falhou: {client_ip}")
                channel.close()
                return
            
            # Cliente autenticado - interagir com shell fake
            self._handle_shell(channel, server_interface.username, client_ip)
        
        except paramiko.AuthenticationException as e:
            self.logger.warning(f"[!] Erro de autenticação SSH: {e}")
        
        except Exception as e:
            self.logger.error(f"Erro ao lidar com cliente: {e}")
        
        finally:
            if transport:
                transport.close()
    
    def _handle_shell(self, channel: paramiko.Channel, username: str, client_ip: str):
        """
        Simula shell interativo.
        Captura comandos e registra no logger.
        """
        try:
            channel.send(f"Welcome to APATE SSH Honeypot\r\n")
            channel.send(f"{username}@honeypot:~$ ")
            
            while True:
                data = channel.recv(1024)
                
                if not data:
                    break
                
                command = data.decode('utf-8', errors='ignore').strip()
                
                if not command:
                    channel.send(f"{username}@honeypot:~$ ")
                    continue
                
                # PREVENIR PATH TRAVERSAL
                dangerous_patterns = ['../', '..\\', '~/..', '/etc/shadow', '/root/']
                if any(pattern in command for pattern in dangerous_patterns):
                    self.logger.warning(f"[!] Path traversal tentado: {username}@{client_ip}: {command}")
                    channel.send("Permission denied\r\n")
                    if self.honey_logger:
                        self.honey_logger.log_command_execution(
                            username, command, client_ip, success=False
                        )
                    channel.send(f"{username}@honeypot:~$ ")
                    continue
                
                # Log do comando
                self.logger.info(f"[CMD] {username}@{client_ip}: {command}")
                if self.honey_logger:
                    self.honey_logger.log_command_execution(
                        username, command, client_ip, success=True
                    )
                
                # Responder com comando fake
                response = self._execute_fake_command(command, username)
                channel.send(response + f"\r\n{username}@honeypot:~$ ")
        
        except Exception as e:
            self.logger.error(f"Erro no shell: {e}")
        
        finally:
            channel.close()
    
    def _execute_fake_command(self, command: str, username: str) -> str:
        """
        Simula execução de comandos comuns.
        Retorna respostas realistas.
        """
        command_lower = command.lower()
        
        if command_lower in ['ls', 'ls -la']:
            return "total 48\ndrwxr-xr-x  5 user  staff   160 May  3 10:00 .\ndrwxr-xr-x  3 root  wheel   96 May  2 14:00 ..\n-rw-r--r--  1 user  staff  1234 May  3 10:00 file1.txt\n-rw-r--r--  1 user  staff  5678 May  3 09:30 file2.log"
        
        elif command_lower == 'whoami':
            return username
        
        elif command_lower == 'pwd':
            return "/home/" + username
        
        elif command_lower == 'id':
            return f"uid=1000({username}) gid=1000({username}) groups=1000({username})"
        
        elif command_lower.startswith('cat '):
            filename = command_lower.replace('cat ', '').strip()
            if 'passwd' in filename:
                return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
            return f"cat: {filename}: No such file or directory"
        
        elif command_lower in ['uname -a', 'uname']:
            return "Linux honeypot 5.15.0-1-generic #1 SMP x86_64 GNU/Linux"
        
        elif command_lower in ['ifconfig', 'ip addr']:
            return "eth0: flags=UP,BROADCAST,RUNNING\n        inet 192.168.1.100  netmask 255.255.255.0"
        
        elif command_lower == 'exit':
            return "exit"
        
        else:
            return f"Command '{command}' not found or error"
    
    def stop(self):
        """Para o servidor"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
            self.logger.info("[+] Servidor SSH parado")