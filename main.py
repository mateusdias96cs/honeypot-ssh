#!/usr/bin/env python3

import os
import sys
import signal
import logging
from pathlib import Path
from dotenv import load_dotenv
import warnings

# Restore SIGINT to default so Ctrl+C works even when started as a background process
signal.signal(signal.SIGINT, signal.default_int_handler)

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
from src.logging.analyzer import BehaviorAnalyzer
from src.logging.threat_intel import ThreatIntelligence
from src.core.rate_limiter import IPRateLimiter

# Carregar .env
load_dotenv()

# Configurar logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
# Mascarar IPs nos logs
class IPMaskFilter(logging.Filter):
    def filter(self, record):
        record.msg = str(record.msg).replace('192.168.15.9', '45.33.32.156')
        record.msg = str(record.msg).replace('192.168.15.8', '10.0.0.1')
        if record.args:
            args_str = str(record.args)
            args_str = args_str.replace('192.168.15.9', '45.33.32.156')
            args_str = args_str.replace('192.168.15.8', '10.0.0.1')
            record.args = None
            record.msg = record.msg + args_str if args_str != 'None' else record.msg
        return True

logging.getLogger().addFilter(IPMaskFilter())
logging.getLogger('paramiko').setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)

def main():
    """Inicia o honeypot SSH"""
        
    logger.info("[+] APATE SSH Honeypot iniciando...")
    try:
        from abertura import BANNER
        print(BANNER)
    except Exception:
        pass
    
    
    
    
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
        pass
    finally:
        logger.info("[+] Encerrando honeypot...")
        server.stop()

        events = honey_logger.get_events()
        if events:
            analyzer = BehaviorAnalyzer(events)
            print("\n" + analyzer.generate_report())
        else:
            print("\n[!] Nenhum evento capturado.")

        sys.exit(0)

if __name__ == '__main__':
    main()