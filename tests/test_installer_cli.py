from pathlib import Path
import os
import pty
import pwd
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import termios
import time
import unittest

@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'Requires macOS Swift')
class HeadlessInstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        source = Path('packaging/Setup.swift').read_text().split('umask(0o077)')[0]
        harness = '''
if CommandLine.arguments.count > 1 && CommandLine.arguments[1] == "--prompt" {
    do { _ = try terminalPrompt("Secret token", secret:true); print("Prompt complete"); exit(0) }
    catch { fputs("Prompt cancelled: \\(error)\\n", stderr); exit(1) }
}
if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--hold-lock" {
    do {
        let held = try SSHInstallerLock(path:CommandLine.arguments[2], owner:getuid())
        print("Locked"); fflush(stdout)
        withExtendedLifetime(held) { _ = readLine() }
        exit(0)
    } catch { fputs("Lock rejected\\n", stderr); exit(1) }
}
if CommandLine.arguments.count == 4 && CommandLine.arguments[1] == "--stage" {
    do {
        _ = try stageCLIAssets(package:URL(fileURLWithPath:CommandLine.arguments[2]), executable:URL(fileURLWithPath:CommandLine.arguments[0]), in:URL(fileURLWithPath:CommandLine.arguments[3]))
        exit(0)
    } catch { fputs("Staging failed\\n", stderr); exit(1) }
}
'''
        main = root / 'main.swift'
        main.write_text(source + '\n' + harness + Path('tests/InstallerCLITests.swift').read_text())
        cls.checks = root / 'checks'
        cls.binary = root / 'OrbitSetup'
        for src, binary in ((main, cls.checks), (Path('packaging/Setup.swift'), cls.binary)):
            subprocess.run(['swiftc','-module-cache-path',str(root/'cache'),str(src),'-o',str(binary)],check=True,capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_credentials_and_logged_out_tracker_lifecycle(self):
        result = subprocess.run([str(self.checks)],check=True,text=True,capture_output=True,timeout=60)
        self.assertIn('checks passed', result.stdout)

    def test_cli_stops_before_changes_without_administrator_access(self):
        if os.getuid() == 0: self.skipTest('Requires unprivileged caller')
        result = subprocess.run([str(self.binary),'--install-cli','/missing/Orbit.pkg','--user','daughter','--credentials-stdin'],input='{}',text=True,capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('sudo', result.stderr)
        self.assertNotIn('osascript', result.stderr)

    def prompt(self, interrupt=None):
        # The unittest runner may already have HTTP-server threads. Never run
        # Python code after forkpty(): macOS/Python can deadlock before exec.
        master, slave = pty.openpty()
        process = None
        try:
            process = subprocess.Popen([str(self.checks), '--prompt'],
                stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
        except BaseException:
            os.close(master)
            raise
        finally:
            os.close(slave)
        output = b''
        try:
            deadline = time.monotonic() + 5
            while b'Secret token: ' not in output:
                if time.monotonic() > deadline: self.fail('Prompt did not appear: ' + repr(output))
                if select.select([master],[],[],0.1)[0]: output += os.read(master,4096)
            self.assertFalse(termios.tcgetattr(master)[3] & termios.ECHO, 'Secret echo must be disabled before displaying the prompt')
            if interrupt:
                process.send_signal(interrupt)
            else:
                os.write(master, b'canary-token-must-not-be-echoed\n')
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    break
                if time.monotonic() > deadline: self.fail('Prompt process did not exit')
                time.sleep(0.01)
            self.assertTrue(termios.tcgetattr(master)[3] & termios.ECHO, 'Terminal echo must be restored after completion or interruption')
            self.assertEqual(process.returncode, 128 + interrupt if interrupt else 0)
            while select.select([master],[],[],0)[0]:
                try: data = os.read(master,4096)
                except OSError: break
                if not data: break
                output += data
            self.assertNotIn(b'canary-token-must-not-be-echoed', output)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            os.close(master)

    def test_hidden_prompt_does_not_echo_secret_and_restores_terminal(self):
        self.prompt()

    def test_interrupts_restore_terminal_echo(self):
        for value in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
            with self.subTest(signal=value): self.prompt(value)

    def test_staged_assets_have_safe_ownership_permissions_and_no_copied_acl(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / 'fixture.pkg'
            subprocess.run(['/usr/bin/pkgbuild','--nopayload','--identifier','com.sideforge.orbit.test','--version','1.0.0',str(package)],check=True,capture_output=True)
            subprocess.run(['/bin/chmod','+a',f'user:{pwd.getpwuid(os.getuid()).pw_name} allow write',str(package)],check=True,capture_output=True)
            stage = root / 'stage'
            alias = root / 'installer-alias'; alias.symlink_to(self.checks)
            subprocess.run([str(alias),'--stage',str(package),str(stage)],check=True,capture_output=True)
            self.assertEqual(stat.S_IMODE(stage.stat().st_mode),0o711)
            for name, mode in (('Orbit.pkg',0o600), ('OrbitSetup',0o755)):
                file = stage / name
                self.assertFalse(file.is_symlink(), 'Staging must copy executable bytes, not a symlink into an untrusted directory')
                self.assertEqual(stat.S_IMODE(file.stat().st_mode),mode)
                self.assertEqual(file.stat().st_uid,os.getuid())
                permissions = subprocess.run(['/bin/ls','-le',str(file)],check=True,text=True,capture_output=True).stdout
                self.assertNotIn('allow write', permissions)
            failed = root / 'failed'
            result = subprocess.run([str(self.checks),'--stage',str(root/'missing.pkg'),str(failed)],capture_output=True)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(stat.S_IMODE(failed.stat().st_mode),0o700, 'Failed staging must remain private')

    def test_concurrent_installs_are_excluded_and_release_the_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'installer.lock'
            first = subprocess.Popen([str(self.checks),'--hold-lock',str(path)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                self.assertTrue(select.select([first.stdout],[],[],5)[0], 'First installer did not acquire the lock')
                self.assertEqual(first.stdout.readline().strip(),'Locked')
                second = subprocess.run([str(self.checks),'--hold-lock',str(path)],input='\n',text=True,capture_output=True,timeout=5)
                self.assertNotEqual(second.returncode,0, 'Simultaneous installers must not share the same lock')
                first.communicate('\n',timeout=5)
                self.assertEqual(first.returncode,0)
                third = subprocess.run([str(self.checks),'--hold-lock',str(path)],input='\n',text=True,capture_output=True,timeout=5)
                self.assertEqual(third.returncode,0,third.stderr)
                crashed = subprocess.Popen([str(self.checks),'--hold-lock',str(path)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                try:
                    self.assertTrue(select.select([crashed.stdout],[],[],5)[0])
                    self.assertEqual(crashed.stdout.readline().strip(),'Locked')
                    crashed.kill(); crashed.communicate(timeout=5)
                    recovered = subprocess.run([str(self.checks),'--hold-lock',str(path)],input='\n',text=True,capture_output=True,timeout=5)
                    self.assertEqual(recovered.returncode,0,'A crashed installer must release its lock without manual cleanup')
                finally:
                    if crashed.poll() is None: crashed.kill(); crashed.communicate()
                self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
                os.chmod(path,0o666)
                rejected = subprocess.run([str(self.checks),'--hold-lock',str(path)],input='\n',text=True,capture_output=True,timeout=5)
                self.assertNotEqual(rejected.returncode,0,'Unsafe existing locks must be rejected')
                os.chmod(path,0o600)
                alias = Path(directory) / 'alias'; alias.symlink_to(path)
                rejected = subprocess.run([str(self.checks),'--hold-lock',str(alias)],input='\n',text=True,capture_output=True,timeout=5)
                self.assertNotEqual(rejected.returncode,0,'Lock symlinks must be rejected')
                hardlink = Path(directory) / 'hardlink'; os.link(path,hardlink)
                rejected = subprocess.run([str(self.checks),'--hold-lock',str(path)],input='\n',text=True,capture_output=True,timeout=5)
                self.assertNotEqual(rejected.returncode,0,'Hard-linked locks must be rejected')
            finally:
                if first.poll() is None: first.kill(); first.communicate()

    def test_desktop_launcher_rejects_cli_flags_without_entering_gui(self):
        environment = {k:v for k,v in os.environ.items() if k not in ('SSH_TTY','SSH_CONNECTION')}
        result = subprocess.run(['/bin/bash','packaging/Install-Orbit.command','--user','daughter'],env=environment,text=True,capture_output=True)
        self.assertEqual(result.returncode,2)
        self.assertIn('--cli',result.stderr)
        self.assertNotIn('Installation did not complete',result.stdout)

if __name__ == '__main__': unittest.main()
