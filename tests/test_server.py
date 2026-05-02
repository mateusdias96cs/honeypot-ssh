import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.auth import AuthenticationManager
from src.core.shell import ShellSimulator
from src.core.filesystem import VirtualFilesystem
from src.security.fingerprint import FingerprintMitigation
from src.logging.analyzer import BehaviorAnalyzer
from src.logging.threat_intel import ThreatIntelligence

class TestAuthentication(unittest.TestCase):

    def setUp(self):
        self.auth = AuthenticationManager()

    def test_valid_login(self):
        success, user = self.auth.authenticate('PC', 'carlos2022')
        self.assertTrue(success)
        self.assertIsNotNone(user)

    def test_invalid_password(self):
        success, user = self.auth.authenticate('PC', 'senha_errada')
        self.assertFalse(success)
        self.assertIsNone(user)

    def test_nonexistent_user(self):
        success, user = self.auth.authenticate('naoexiste', '123')
        self.assertFalse(success)

class TestShell(unittest.TestCase):

    def setUp(self):
        self.fs = VirtualFilesystem()
        self.shell = ShellSimulator('PC', '/home/PC', filesystem=self.fs)

    def test_whoami(self):
        self.assertEqual(self.shell.execute_command('whoami'), 'PC')

    def test_pwd(self):
        self.assertEqual(self.shell.execute_command('pwd'), '/home/PC')

    def test_unknown_command(self):
        result = self.shell.execute_command('naoexiste')
        self.assertIn('command not found', result)

    def test_ls(self):
        result = self.shell.execute_command('ls')
        self.assertIsNotNone(result)

class TestFilesystem(unittest.TestCase):

    def setUp(self):
        self.fs = VirtualFilesystem()

    def test_list_directory(self):
        files = self.fs.list_directory('/home/PC')
        self.assertIsNotNone(files)
        self.assertIn('Documents', files)

    def test_read_file(self):
        content = self.fs.read_file('/etc/hostname')
        self.assertIn('webserver01', content)

    def test_is_locked(self):
        self.assertTrue(self.fs.is_locked('/home/PC/secret_vault'))

class TestFingerprint(unittest.TestCase):

    def setUp(self):
        self.fp = FingerprintMitigation()

    def test_banner(self):
        banner = self.fp.get_realistic_ssh_banner()
        self.assertIn(b'SSH-2.0-OpenSSH', banner)
        self.assertTrue(banner.endswith(b'\r\n'))

class TestAnalyzer(unittest.TestCase):

    def setUp(self):
        self.events = [
            {'type': 'auth_attempt', 'ip': '192.168.1.1', 'username': 'root', 'success': False},
            {'type': 'auth_attempt', 'ip': '192.168.1.1', 'username': 'root', 'success': False},
            {'type': 'auth_attempt', 'ip': '192.168.1.1', 'username': 'root', 'success': False},
            {'type': 'auth_attempt', 'ip': '192.168.1.1', 'username': 'root', 'success': False},
            {'type': 'auth_attempt', 'ip': '192.168.1.1', 'username': 'root', 'success': False},
            {'type': 'auth_attempt', 'ip': '192.168.1.1', 'username': 'root', 'success': False},
        ]
        self.analyzer = BehaviorAnalyzer(self.events)

    def test_brute_force_detection(self):
        patterns = self.analyzer.detect_attack_patterns()
        types = [p['type'] for p in patterns]
        self.assertIn('brute_force', types)

class TestThreatIntel(unittest.TestCase):

    def setUp(self):
        self.ti = ThreatIntelligence()

    def test_malicious_ip(self):
        result = self.ti.check_ip_reputation('192.168.1.100')
        self.assertEqual(result['reputation'], 'malicious')

    def test_unknown_ip(self):
        result = self.ti.check_ip_reputation('8.8.8.8')
        self.assertEqual(result['reputation'], 'unknown')

if __name__ == '__main__':
    unittest.main()