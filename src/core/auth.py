import bcrypt
import json
import logging
from pathlib import Path
from typing import Tuple, Optional, Dict


class AuthenticationManager:
    """
    Gerenciador de autenticação com hash bcrypt.
    Suporta migração automática de senhas plaintext.
    """
    
    def __init__(self, config: Dict):
        self.logger = logging.getLogger(__name__)
        self.users = config.get('users', {})
        self.db_path = Path(config.get('db_path', 'data/users.json'))
        
        # Converter senhas plaintext para bcrypt
        self._ensure_hashed_passwords()
        self._save_to_file()
    
    def _ensure_hashed_passwords(self) -> None:
        """Converte senhas plaintext para bcrypt hash"""
        changed = False
        
        for username, user_data in self.users.items():
            stored_password = user_data.get('password', '')
            
            # Se não é hash bcrypt, converter
            if not stored_password.startswith('$2b$'):
                self.logger.info(f"[!] Convertendo plaintext para bcrypt: {username}")
                user_data['password'] = self.hash_password(stored_password)
                changed = True
        
        if changed:
            self.logger.info("[+] Senhas convertidas para bcrypt")
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Cria hash bcrypt de senha.
        
        Args:
            password: Senha em plaintext
        
        Returns:
            Hash bcrypt com salt
        """
        salt = bcrypt.gensalt(rounds=14)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """
        Verifica senha contra hash bcrypt.
        
        Args:
            password: Senha em plaintext
            hashed: Hash bcrypt armazenado
        
        Returns:
            True se a senha está correta
        """
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception as e:
            logging.error(f"Erro ao verificar senha: {e}")
            return False
    
    def authenticate(self, username: str, password: str) -> Tuple[bool, Optional[Dict]]:
        """
        Autentica usuário contra banco de dados.
        
        Args:
            username: Nome de usuário
            password: Senha em plaintext
        
        Returns:
            Tupla (success: bool, user_data: Dict ou None)
        """
        if not username or not password:
            return False, None
        
        user_data = self.users.get(username)
        
        if not user_data:
            self.logger.warning(f"[!] Usuário não encontrado: {username}")
            return False, None
        
        stored_password = user_data.get('password', '')
        
        if self.verify_password(password, stored_password):
            self.logger.info(f"[✓] Autenticação bem-sucedida: {username}")
            return True, {'username': username, **user_data}
        else:
            self.logger.warning(f"[✗] Falha de autenticação: {username}")
            return False, None
    
    def add_user(self, username: str, password: str) -> bool:
        """Adiciona novo usuário com senha hasheada"""
        if username in self.users:
            self.logger.warning(f"[!] Usuário já existe: {username}")
            return False
        
        self.users[username] = {
            'password': self.hash_password(password),
            'created_at': str(Path.cwd())
        }
        self._save_to_file()
        self.logger.info(f"[+] Usuário criado: {username}")
        return True
    
    def _save_to_file(self) -> None:
        """Salva usuários em arquivo JSON (opcional)"""
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            # Não salvar passwords em arquivo real - apenas em memória
            # Esta é apenas uma estrutura
        except Exception as e:
            self.logger.error(f"Erro ao salvar usuários: {e}")