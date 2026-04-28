import socket
import threading
import logging
import time
from typing import Optional, Tuple

class SSHHoneypotServer:
    """
    Servidor SSH Honeypot - Núcleo da aplicação
    Responsável por aceitar e gerenciar conexões
    """

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        self.logger = logging.getLogger(__name__)
        self.running = False
        self.active_connections = []
        self.max_threads = 50

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

        
        """
        TAREFA #2: Implemente esta função!
        1. ADICIONAR conexão à lista de ativas
        2. REGISTRAR conexão com logger
        3. ENVIAR banner SSH
        4. MANTER conexão aberta (placeholder)
        5. REMOVER de conexões ativas
        6. FECHAR conexão
        """
        try:
            self.active_connections.append(addr)
            self.logger.info(f"Conexão {addr}")
            banner = b"SSH-2.0-OpenSSH_8.2\r\n"
            conn.sendall(banner)
            time.sleep(1)
            
            
        except Exception as e:
            self.logger.error(f"[-] Erro ao processar {addr}: {e}")
        finally:
            try:
                if addr in self.active_connections:
                    self.active_connections.remove(addr)
                conn.close()
            except:
                pass

    def start(self) -> None:
        """
        TAREFA #2: Implemente esta função!
        1. CRIAR socket
        2. ENQUANTO running:
            a. ACEITAR conexão
            b. VERIFICAR se não excedeu max_threads
            c. CRIAR nova thread
            d. INICIAR thread com handle_connection
        """
        self.create_server_socket()
        self.running = True

        try:
            self.logger.info("[*] Aguardando conexões...")

            # ========== REESCREVA ESTA SEÇÃO ==========
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
            # ==========================================

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