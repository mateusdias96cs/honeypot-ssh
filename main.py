#!/usr/bin/env python3
import sys
import logging
import argparse
from pathlib import Path

from config.settings import CONFIG
from src.core.server import SSHHoneypotServer
from src.core.auth import AuthenticationManager
from src.core.filesystem import VirtualFilesystem
from src.security.fingerprint import FingerprintMitigation
from src.security.deception import DeceptionEngine
from src.security.anti_detect import AntiDetection
from src.logging.logger import HoneypotLogger
from src.logging.analyzer import BehaviorAnalyzer
from src.logging.threat_intel import ThreatIntelligence

def setup_logging_system(debug_mode: bool = False) -> logging.Logger:
    logger = logging.getLogger('honeypot')
    level = logging.DEBUG if debug_mode else logging.INFO
    logger.setLevel(level)
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s - %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

def initialize_components(config: dict, logger: logging.Logger) -> dict:
    logger.info("[*] Inicializando componentes...")
    components = {
        'auth': AuthenticationManager(config.get('users_file')),
        'filesystem': VirtualFilesystem(),
        'fingerprint': FingerprintMitigation(),
        'deception': DeceptionEngine(),
        'anti_detect': AntiDetection(),
        'logger': HoneypotLogger(
            config.get('log_file'),
            config.get('internal_log')
        ),
        'threat_intel': ThreatIntelligence(),
    }
    logger.info("[+] Componentes inicializados com sucesso")
    return components

def start_honeypot(config: dict, components: dict, logger: logging.Logger) -> None:
    try:
        logger.info(f"[+] Iniciando SSH Honeypot")
        logger.info(f"[+] Host: {config['host']}:{config['port']}")

        server = SSHHoneypotServer(config['host'], config['port'])
        logger.info("[*] Aguardando conexões...")
        server.start()

    except KeyboardInterrupt:
        logger.info("\n[!] Servidor interrompido pelo usuário (Ctrl+C)")

    except Exception as e:
        logger.error(f"[-] Erro no servidor: {e}")

    finally:
        try:
            honey_logger = components.get('logger')
            if honey_logger:
                events = honey_logger.get_events()
                analyzer = BehaviorAnalyzer(events)
                report = analyzer.generate_report()
                logger.info(f"\n{report}")

                threat_intel = components.get('threat_intel')
                if threat_intel:
                    summary = threat_intel.get_threat_summary(events)
                    logger.info(f"[!] Resumo de ameaças: {summary}")

            logger.info("[+] Honeypot finalizado")
        except Exception as e:
            logger.error(f"[-] Erro ao gerar relatório: {e}")

def main() -> None:
    parser = argparse.ArgumentParser(description='SSH Honeypot Profissional')
    parser.add_argument('--debug', action='store_true', help='Modo debug')
    parser.add_argument('--port', type=int, help='Porta customizada')
    parser.add_argument('--host', default='0.0.0.0', help='Host')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0.0')
    args = parser.parse_args()

    if args.port:
        CONFIG['port'] = args.port
    if args.host:
        CONFIG['host'] = args.host
    CONFIG['debug_mode'] = args.debug

    logger = setup_logging_system(args.debug)

    logger.info("=" * 60)
    logger.info("SSH HONEYPOT PROFISSIONAL v1.0.0")
    logger.info("=" * 60)

    components = initialize_components(CONFIG, logger)
    start_honeypot(CONFIG, components, logger)

if __name__ == '__main__':
    main()