import subprocess
import os
import logging
from typing import Dict, Optional

class AntiDetection:
    """Máscarar máquina virtual"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.is_vm = self._detect_vm()

    def _detect_vm(self) -> bool:
        
        try:
            with open('/proc/cpuinfo', 'r') as f:
                if 'hypervisor' in f.read():
                    return True
        except:
            pass

        try:
            with open('/sys/class/dmi/id/sys_vendor', 'r') as f:
                content = f.read().lower()
                if 'qemu' in content or 'vmware' in content or 'virtualbox' in content:
                    return True
        except:
            pass

        return False
     
   
    def get_obfuscated_system_info(self) -> Dict:

        try:
            info = {
                'kernel': '5.15.0-84-generic',
                'architecture': 'x86_64',
                'hostname': 'webserver01',
                'cpu_model': 'Intel Xeon E5-2680 v4 @ 2.40GHz',
                'cpu_cores': '28',
                'memory': '64GB ECC DDR4',
                'uptime': '127 days, 14:32:01',
            
            }
            return info
        
        except Exception as e:
            self.logger.error(f"[-] Erro ao obter info do sistema: {e}")
            return {}
            