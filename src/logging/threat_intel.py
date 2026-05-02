import logging
import requests
from typing import Dict, Optional
from functools import lru_cache

class ThreatIntelligence:
    """Integração com threat intelligence"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.known_threats = self._load_threat_database()

    @lru_cache(maxsize=1000)
    def check_ip_reputation(self, ip: str) -> Dict:
        try:
            result = {
                'ip': ip,
                'reputation': 'unknown',
                'threat_level': 0,
                'description': ''
            }

            if ip in self.known_threats:
                result.update(self.known_threats[ip])
            
            return result
        except Exception as e:
            self.logger.error(f"[-] Erro ao verificar IP: {e}")
            return {'ip': ip, 'reputation': 'error', 'threat_level': 0}
    
    def _load_threat_database(self) -> Dict:
        """Base de dados local de IPs conhecidos (demo)"""
        return {
            '192.168.1.100': {
                'reputation': 'malicious',
                'threat_level': 9,
                'description': 'Known botnet C&C server'
            },
            '10.0.0.50': {
                'reputation': 'suspicious',
                'threat_level': 6,
                'description': 'Frequent brute force attempts'
            },
        }

    def get_threat_summary(self, events: list) -> Dict:
        """Gerar resumo de ameaças"""
        ips = set()
        for event in events:
            ips.add(event.get('ip'))

        summary = {
            'total_ips': len(ips),
            'malicious_ips': 0,
            'suspicious_ips': 0,
            'threats': []
        }

        for ip in ips:
            reputation = self.check_ip_reputation(ip)
            if reputation['threat_level'] >= 8:
                summary['malicious_ips'] += 1
            elif reputation['threat_level'] >= 5:
                summary['suspicious_ips'] += 1

            summary['threats'].append(reputation)

        return summary