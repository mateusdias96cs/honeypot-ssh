import socket
import sys

class SSHHoneypotServer:
    

    def __init__(self, host, port):
        """
        Inicializa o servidor
        """
    
        self.host = host
        self.port = port
        self.server_socket = None

    def create_server_socket(self):

        """
        Cria e configura socket TCP
        """
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        self.server_socket = server_socket

if __name__ == "__main__":
        SSHHoneypot = SSHHoneypotServer("0.0.0.0", 2222)
        SSHHoneypot.create_server_socket()
        print("Servidor iniciando na porta 2222")
        conn, addr = SSHHoneypot.server_socket.accept()
        conn.close()
        SSHHoneypot.server_socket.close()

    


