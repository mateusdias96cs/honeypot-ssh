#!/usr/bin/env python3

import os
import sys
import logging
from pathlib import Path
from dotenv import load_dotenv
import warnings

# Suppress cryptography deprecation warnings from paramiko
try:
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except ImportError:
    pass

# Adicionar src ao path
sys.path.insert(0, str(Path(__file__).parent))

from src.core.auth import AuthenticationManager
from src.core.server import SSHHoneypotServer
from src.logging.logger import HoneypotLogger
from src.logging.threat_intel import ThreatIntelligence
from src.core.rate_limiter import IPRateLimiter

# Carregar .env
load_dotenv()

# Configurar logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Inicia o honeypot SSH"""
    
    logger.info("[+] APATE SSH Honeypot iniciando...")
    
    # Criar diretórios necessários
    Path("logs").mkdir(exist_ok=True)
    Path("data").mkdir(exist_ok=True)
    
    # Configurar componentes
    config = {
        'users': {
            'admin': {'password': 'admin123'},
            'carlos': {'password': 'senha_123'},
            'test': {'password': 'test123'}
        },
        'db_path': 'data/users.json'
    }
    
    # Inicializar componentes
    auth_manager = AuthenticationManager(config)
    honey_logger = HoneypotLogger()
    threat_intel = ThreatIntelligence() if os.getenv('ENABLE_THREAT_INTEL') == 'true' else None
    rate_limiter = IPRateLimiter(
        max_connections=int(os.getenv('RATE_LIMIT_MAX_CONNECTIONS', 10)),
        time_window=int(os.getenv('RATE_LIMIT_TIME_WINDOW', 60))
    )
    
    # Componentes
    components = {
        'auth': auth_manager,
        'logger': honey_logger,
        'threat_intel': threat_intel,
        'rate_limiter': rate_limiter
    }
    
    # Iniciar servidor SSH
    server = SSHHoneypotServer(components)
    
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("[+] Encerrando honeypot...")
        server.stop()
        sys.exit(0)

if __name__ == '__main__':
    main()