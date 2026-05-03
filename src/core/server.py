import socket
import threading
import logging
import time
from collections import defaultdict
from typing import Optional, Tuple
from src.core.shell import ShellSimulator
from src.core.filesystem import VirtualFilesystem

class IPRateLimiter:
    def __init__(self, max_connections: int, time_window: int):
        self.max_connections = max_connections
        self.time_window = time_window
        self.connections = defaultdict(list)
        self.lock = threading.Lock()

    def is_allowed(self, ip: str) -> bool:
        with self.lock:
            now = time.time()
            self.connections[ip] = [t for t in self.connections[ip] if now - t < self.time_window]
            if len(self.connections[ip]) >= self.max_connections:
                return False
            self.connections[ip].append(now)
            return True

class SSHHoneypotServer:
    """
    Servidor SSH Honeypot - Núcleo da aplicação
    Responsável por aceitar e gerenciar conexões
    """

    def __init__(self, host: str, port: int, components: dict = None):
        self.host = host
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        self.logger = logging.getLogger(__name__)
        self.running = False
        self.active_connections = []
        self.max_threads = 50
        components = components or {}
        self.honey_logger = components.get('logger')
        self.filesystem = components.get('filesystem')
        self.threat_intel = components.get('threat_intel')
        self.rate_limiter = IPRateLimiter(max_connections=10, time_window=60)

    def create_server_socket(self) -> None:
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            self.server_socket = server_socket
            self.logger.info(f"[+] Servidor iniciado em {self.host}:{self.port}")
        except Exception as e:
            self.logger.error(f"[-] Erro ao criar socket: {e}")
            raise

    def handle_connection(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        client_ip = addr[0]
        try:
            # Check threat intel first to block known bad actors
            if self.threat_intel:
                reputation = self.threat_intel.check_ip_reputation(client_ip)
                if reputation.get('threat_level', 0) >= 8:
                    self.logger.warning(f"[!] Conexão bloqueada de {client_ip} devido à má reputação.")
                    conn.close()
                    return

            # Check rate limiting
            if not self.rate_limiter.is_allowed(client_ip):
                self.logger.warning(f"[!] Rate limit excedido para {client_ip}.")
                conn.close()
                return

            self.active_connections.append(addr)
            self.logger.info(f"Conexão recebida de {addr}")
            
            # Envia banner
            banner = b"SSH-2.0-OpenSSH_8.2\r\n"
            conn.sendall(banner)
            
            # Pede usuario
            conn.sendall(b"login: ")
            username = conn.recv(1024).decode().strip()
            
            # Pede senha
            conn.sendall(b"Password: ")
            password = conn.recv(1024).decode().strip()
            
            # Log authentication attempt
            if self.honey_logger:
                self.honey_logger.log_authentication_attempt(
                    username, password, client_ip, success=True
                )
            
            # Simula autenticacao
            conn.sendall(f"\nWelcome to Ubuntu 20.04.6 LTS\r\n".encode())
            conn.sendall(f"Last login: Fri Apr 25 10:02:01 2026 from 192.168.1.5\r\n\r\n".encode())
            
            # Shell interativo
            fs = self.filesystem or VirtualFilesystem()
            shell = ShellSimulator(
                username or 'PC', '/home/PC', filesystem=fs,
                honey_logger=self.honey_logger, client_ip=client_ip
            )
            
            while True:
                conn.sendall(shell.get_prompt().encode())
                data = conn.recv(1024)
                if not data:
                    break
                command = data.decode().strip()
                if command in ('exit', 'quit', 'logout'):
                    conn.sendall(b"logout\r\n")
                    break
                result = shell.execute_command(command)
                if result:
                    conn.sendall(f"{result}\r\n".encode())
            
        except Exception as e:
            self.logger.error(f"[-] Erro ao processar {addr}: {e}")
        finally:
            try:
                # Check IP reputation after session ends
                if self.threat_intel:
                    reputation = self.threat_intel.check_ip_reputation(client_ip)
                    if reputation.get('threat_level', 0) > 0:
                        self.logger.warning(
                            f"[!] Threat Intel para {client_ip}: "
                            f"{reputation.get('reputation')} "
                            f"(nível {reputation.get('threat_level')})"
                        )
                if addr in self.active_connections:
                    self.active_connections.remove(addr)
                conn.close()
            except:
                pass

    def start(self) -> None:

        self.create_server_socket()
        self.running = True

        try:
            self.logger.info("[*] Aguardando conexões...")

            
            while self.running:
                try:
                    conn, addr = self.server_socket.accept()
                    
                    if len(self.active_connections) < self.max_threads:
                        thread = threading.Thread(target=self.handle_connection, args=(conn, addr))
                        thread.daemon = True
                        thread.start()
                    else:
                        conn.close()
                    
                except KeyboardInterrupt:
                    break
            

        except Exception as e:
            self.logger.error(f"[-] Erro no servidor: {e}")
        finally:
            self.running = False
            if self.server_socket:
                self.server_socket.close()
            self.logger.info("[!] Servidor finalizado")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    server = SSHHoneypotServer("0.0.0.0", 2222)
    server.start()