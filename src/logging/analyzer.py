import logging
from typing import Dict, List, Optional
from collections import defaultdict
from datetime import datetime, timedelta


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
    
    def detect_attack_patterns(self) -> List[Dict]:
        

        try:
            alerts = []

            auth_analysis = self.analyze_authentication_attempts()
            for ip, data in auth_analysis.items():
                if data.get('failed', 0 ) > 5:
                    alerts.append({
                        'type': 'brute_force',
                        'ip': ip,
                        'failed_attempts': data.get('failed'),
                        'severity': 'high'
                    })

            for event in self.events:
                if "sudo" in event.get('command', ''):
                    alerts.append({
                        "type": "privilege_escalation",
                        "user": event.get('username'),
                        "severity": "high"
                    })
            recon_commands = ["whoami", "id", "uname", "hostname", "ifconfig", "netstat"]
            recon_count = {}

            for event in self.events:
                if event.get('type') == 'command_execution':
                    ip = event.get('ip')
                command = event.get('command', '')
                if any(cmd in command for cmd in recon_commands):
                    recon_count[ip] = recon_count.get(ip, 0) + 1

            for ip, count in recon_count.items():   
                if count >= 3:
                    alerts.append({
                        'type': 'reconnaissance',
                        'ip': ip,
                        'count': count,
                        'severity': 'medium'
                    })
            
            for event in self.events:
                if event.get('type') == "command_execution":
                    if "ssh" in event.get('command', ''):
                        alerts.append({
                            'type': 'Lateral Movement',
                            'ip': event.get('ip'),
                            'command': event.get('command'),
                            'severity': 'High'
                        })
            
            arquivos_sensiveis = [".env", "config.yaml", "passwd", "id_rsa", "shadow"]
            for event in self.events:
                if event.get('type') == "file_access":
                    filepath = event.get('filepath', '')
                    if any(arq in filepath for arq in arquivos_sensiveis):
                        alerts.append({
                            'type': 'Data Exfiltration',
                            'ip': event.get('ip'),
                            'filepath': filepath,
                            'severity': 'Critical'
                        })
            for event in self.events:
                if event.get('type') in ('file_access', 'command_execution'):
                    filepath = event.get('filepath', '')
                    command = event.get('command', '')
                    if 'secret_vault' in filepath or 'secret_vault' in command:
                        alerts.append({
                            'type': "honeytoken_triggered",
                            'ip': event.get('ip'),
                            'filepath': filepath,
                            'command': event.get('command'),
                            'severity': "critical"
                        })  
        except Exception as e:
            self.logger.error(f"[-] Erro ao detectar padrões: {e}")
            return []
                        
    def generate_report(self) -> str:
        """Gerar relatório de análise"""
        report = "=" * 60 + "\n"
        report += "HONEYPOT ATTACK ANALYSIS REPORT\n"
        report += "=" * 60 + "\n\n"

        auth_analysis = self.analyze_authentication_attempts()
        report += f"Total de IPs:{len(auth_analysis)}\n"

        patterns = self.detect_attack_patterns()
        report += f"Alertas detectados:{len(patterns)}\n\n"

        for alert in patterns:
            report += f"[{alert['type'].upper()}]{alert}\n"

        return report
        
