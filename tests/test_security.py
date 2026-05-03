import pytest
import time
from src.core.server import SSHHoneypotServer
from src.core.rate_limiter import IPRateLimiter
from src.core.shell import ShellSimulator
from src.core.filesystem import VirtualFilesystem
from src.core.auth import AuthenticationManager
from src.logging.threat_intel import ThreatIntelligence

def test_rate_limiter():
    limiter = IPRateLimiter(max_connections=3, time_window=1)
    ip = "192.168.1.100"
    
    assert limiter.is_allowed(ip) is True
    assert limiter.is_allowed(ip) is True
    assert limiter.is_allowed(ip) is True
    assert limiter.is_allowed(ip) is False # 4th attempt should fail
    
    time.sleep(1.1)
    assert limiter.is_allowed(ip) is True # Should pass after window expires

def test_path_traversal_prevention():
    fs = VirtualFilesystem()
    shell = ShellSimulator("PC", "/home/PC", filesystem=fs)
    
    # Normalizing path correctly limits directory to root if too many ..
    shell.execute_command("cd ../../../etc")
    assert shell.current_dir == "/etc"
    
    # Attempting to read a file with cat path traversal
    # normalize_path should resolve it to /etc/shadow
    # "No such file" since /etc/shadow is not in virtual fs
    result = shell.execute_command("cat ../../../etc/shadow")
    assert "No such file or directory" in result

    # Let's test reading an existing file via traversal
    result = shell.execute_command("cat ../../../etc/passwd")
    assert "root:x:0:0:root:/root:/bin/bash" in result
    
    # Test locked file access bypass attempt
    # The locked file is in /home/PC/secret_vault. Let's try to cd to it
    result = shell.execute_command("cd /home/PC/secret_vault")
    assert "Permission denied" in result

def test_threat_intel_blocking():
    threat_intel = ThreatIntelligence()
    # The default database has 192.168.1.100 as malicious (level 9)
    reputation = threat_intel.check_ip_reputation("192.168.1.100")
    assert reputation['threat_level'] >= 8

def test_bcrypt_hashing(tmp_path):
    users_file = tmp_path / "users.json"
    
    config = {
        'users': {'testuser': {'password': 'plaintextpassword'}},
        'db_path': str(users_file)
    }
    
    auth_mgr = AuthenticationManager(config)
    
    # Password should be converted
    assert auth_mgr.users["testuser"]["password"].startswith("$2b$")
    
    # Test authentication
    success, user = auth_mgr.authenticate("testuser", "plaintextpassword")
    assert success is True
    
    success, user = auth_mgr.authenticate("testuser", "wrongpassword")
    assert success is False
