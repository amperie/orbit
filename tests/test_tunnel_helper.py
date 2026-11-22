import importlib.util
from pathlib import Path
import subprocess
import stat
import sys
import shutil
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

class TunnelHelperTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'Requires macOS Swift')
    def test_swift_security_and_process_lifecycle(self):
        source = Path('tunnel/Tunnel.swift').read_text()
        definitions = source[:source.index('if CommandLine.arguments.count')]
        definitions += source[source.index('func continuousTime()'):source.index('var nextAttempt:')]
        with tempfile.TemporaryDirectory() as directory:
            main = Path(directory) / 'main.swift'
            main.write_text(definitions + Path('tests/TunnelTests.swift').read_text())
            binary = Path(directory) / 'tests'
            subprocess.run(['swiftc', '-module-cache-path', directory + '/cache', str(main), '-o', str(binary)], check=True, capture_output=True)
            result = subprocess.run([str(binary)], check=True, text=True, capture_output=True)
            self.assertIn('checks passed', result.stdout)

    @unittest.skipUnless(sys.platform == 'darwin', 'Uses the macOS OpenSSH configuration parser')
    def test_openssh_accepts_and_enforces_restrictions(self):
        spec = importlib.util.spec_from_file_location('tunnel_setup', 'tunnel/setup.py')
        setup = importlib.util.module_from_spec(spec); spec.loader.exec_module(setup)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-f',str(root / 'host_key')],check=True)
            config = root / 'sshd_config'
            config.write_text(setup.mac_sshd_config('parent', root))
            result = subprocess.run(['/usr/sbin/sshd','-T','-f',str(config),'-C','user=parent,host=localhost,addr=127.0.0.1'],check=True,text=True,capture_output=True).stdout.splitlines()
            for expected in ('port 2222','listenaddress 127.0.0.1:2222','authenticationmethods publickey','passwordauthentication no','kbdinteractiveauthentication no','permitrootlogin no','disableforwarding yes','allowusers parent'):
                self.assertIn(expected, result)
            config.write_text('HostKey "' + str(root / 'host_key') + '"\n' + setup.server_sshd_config('orbit-tunnel', 22001))
            result = subprocess.run(['/usr/sbin/sshd','-T','-f',str(config),'-C','user=orbit-tunnel,host=localhost,addr=127.0.0.1'],check=True,text=True,capture_output=True).stdout.splitlines()
            for expected in ('gatewayports no','allowtcpforwarding remote','permitlisten 127.0.0.1:22001','maxsessions 0','passwordauthentication no','permitopen none','authenticationmethods publickey','allowstreamlocalforwarding no'):
                self.assertIn(expected, result)

    def test_setup_rejects_private_keys_and_symlink_writes(self):
        spec = importlib.util.spec_from_file_location('tunnel_setup', 'tunnel/setup.py')
        setup = importlib.util.module_from_spec(spec); spec.loader.exec_module(setup)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / 'private'; private.write_text('-----BEGIN OPENSSH PRIVATE KEY-----\nsecret')
            with self.assertRaises(ValueError): setup.public_key(private)
            target = root / 'target'; target.write_text('unchanged')
            link = root / 'link'; link.symlink_to(target)
            with self.assertRaises(ValueError): setup.write(link, 'overwritten')
            self.assertEqual(target.read_text(), 'unchanged')
            with patch.object(setup.Path, 'lstat', return_value=SimpleNamespace(st_uid=501, st_mode=stat.S_IFDIR | 0o700)):
                # Existing user-owned directories are never accepted for root helper configuration.
                with self.assertRaises(ValueError): setup.safe_dir(root)

if __name__ == '__main__': unittest.main()
