import subprocess
import logging
import re
from typing import Optional

class FingerprintMitigation:
    


    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._banner_cache = None
    
    def get_realistic_ssh_banner(self) -> bytes:
        if self._banner_cache:
            return self._banner_cache  #Retorna o cache após a primeira inicialização
        
        try:
            result = subprocess.run(["ssh", "-V"], capture_output=True, text=True)
            match = re.search(r'OpenSSH_\S+', result.stderr)
            if match:
                banner = "SSH-2.0-" + match.group()
                self._banner_cache = banner.encode() + b"\r\n"
            return self._banner_cache

        except:
            return b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
    
    def get_system_info(self) -> dict:
        system_info = {
            'kernel': subprocess.check_output(['uname', '-r']).decode().strip(),
            'architecture': subprocess.check_output(['uname', '-m']).decode().strip(),
            'hostname': subprocess.check_output(['hostname']).decode().strip(),
        }
        return system_info

