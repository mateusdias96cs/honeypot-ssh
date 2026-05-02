import logging
from typing import Dict, List, Optional
from collections import defaultdict
from datetime import datetime, timedelta
from src.logging.analyzer import BehaviorAnalyzer

class BehaviorAnalyzer:

    """analisa comportamento do atacante"""

    def __init__(self, events: List[Dict]):
        self.logger = logging.getLogger(__name__)
        self.events = events 
        self.threats = []

    def analyze_authentication_attempts(self) -> Dict:
        try:
            
            analysis = {}

            for event in self.events:
                if event.get('type') != 'auth_attempt':
                    continue

                ip = event.get('ip')
                if ip not in analysis:
                    analysis[ip] = {'attempts': 0, 'success': 0, 'failed': 0}
                
                analysis[ip]['attempts'] += 1
                if event.get('success'):
                    analysis[ip]['success'] += 1
                else:
                    analysis[ip]['failed'] += 1
            
            for ip, dados in analysis.items():
                if dados['failed'] > 5:
                    self.threats.append({
                        'type': 'brute_force',
                        'ip' : ip,
                        'failed': dados['failed']
                    })
            return analysis
                
        
        except Exception as e:
            self.logger.error(f"[-] Erro ao analisar: {e}")
            return {}