import pytest
from src.core.auth import AuthenticationManager


class TestAuthenticationManager:
    """Testes para o gerenciador de autenticação com bcrypt"""
    
    @pytest.fixture
    def auth_manager(self):
        """Fixture para criar um AuthenticationManager de teste"""
        config = {
            'users': {
                'admin': {'password': 'admin123'},
                'carlos': {'password': 'senha_123'},
                'test_user': {'password': 'test123'}
            }
        }
        return AuthenticationManager(config)
    
    def test_hash_password_creates_bcrypt_hash(self, auth_manager):
        """Verifica se hash_password cria hash bcrypt válido"""
        password = "test_password_123"
        hashed = auth_manager.hash_password(password)
        
        assert hashed.startswith('$2b$')
        assert len(hashed) == 60
        assert hashed != password
    
    def test_bcrypt_hashes_are_unique(self, auth_manager):
        """Hashes bcrypt são únicos mesmo para mesma senha"""
        password = "same_password"
        hash1 = auth_manager.hash_password(password)
        hash2 = auth_manager.hash_password(password)
        
        assert hash1 != hash2
    
    def test_authenticate_valid_credentials(self, auth_manager):
        """Testa autenticação com credenciais válidas"""
        success, user = auth_manager.authenticate('admin', 'admin123')
        
        assert success is True
        assert user is not None
        assert user.get('username') == 'admin'
    
    def test_authenticate_invalid_password(self, auth_manager):
        """Testa autenticação com senha incorreta"""
        success, user = auth_manager.authenticate('admin', 'wrong_password')
        
        assert success is False
        assert user is None
    
    def test_authenticate_invalid_username(self, auth_manager):
        """Testa autenticação com usuário não existente"""
        success, user = auth_manager.authenticate('invalid_user', 'password123')
        
        assert success is False
        assert user is None
    
    def test_ensure_hashed_passwords_converts_plaintext(self, auth_manager):
        """Verifica se plaintext é convertido para bcrypt"""
        # Adicionar usuário com plaintext
        auth_manager.users['new_user'] = {'password': 'plaintext_pass'}
        
        auth_manager._ensure_hashed_passwords()
        
        stored_password = auth_manager.users['new_user']['password']
        assert stored_password.startswith('$2b$')
        
        # Verificar autenticação com plaintext
        success, user = auth_manager.authenticate('new_user', 'plaintext_pass')
        assert success is True
    
    def test_password_verification_case_sensitive(self, auth_manager):
        """Verifica que autenticação é case-sensitive"""
        success1, _ = auth_manager.authenticate('admin', 'admin123')
        success2, _ = auth_manager.authenticate('admin', 'Admin123')
        
        assert success1 is True
        assert success2 is False
    
    def test_authenticate_empty_credentials(self, auth_manager):
        """Testa autenticação com credenciais vazias"""
        success1, _ = auth_manager.authenticate('', 'password')
        success2, _ = auth_manager.authenticate('admin', '')
        
        assert success1 is False
        assert success2 is False
