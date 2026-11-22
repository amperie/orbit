#!/usr/bin/env python3
"""One-time, root-only provisioning. No private key ever leaves its machine."""
import argparse
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import subprocess
import sys

ROOT = Path('/Library/Application Support/OrbitTunnel')
SOURCE = Path(__file__).resolve().parent

def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout.strip()

def write(path, contents, mode=0o600):
    path = Path(path)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError('Unsafe file: ' + str(path))
    # Root-owned parent directories are checked before any write.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'w') as stream:
        os.fchmod(stream.fileno(), mode)
        os.fchown(stream.fileno(), 0, 0)
        stream.write(contents)

def safe_dir(path, mode=0o755):
    path = Path(path)
    if not path.exists(): path.mkdir(mode=mode)
    info = path.lstat()
    if path.is_symlink() or not path.is_dir() or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Directory must be root-owned and not writable by others: ' + str(path))

def public_key(path):
    value = Path(path).read_text().strip().split()
    if len(value) < 2 or value[0] != 'ssh-ed25519' or not re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', value[1]):
        raise ValueError('Use an Ed25519 public key file (never a private key)')
    run('/usr/bin/ssh-keygen', '-l', '-f', str(path))
    return ' '.join(value[:2])

def mac_sshd_config(user, root):
    return f'''Port 2222
ListenAddress 127.0.0.1
HostKey "{root}/host_key"
PidFile "{root}/sshd.pid"
AuthorizedKeysFile /private/etc/ssh/orbit-tunnel-parent-key
AllowUsers {user}
AuthenticationMethods publickey
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
UsePAM yes
StrictModes yes
DisableForwarding yes
PermitUserEnvironment no
PermitUserRC no
LogLevel VERBOSE
'''

def mac(args):
    if platform.system() != 'Darwin': raise ValueError('Run --mac on the target Mac')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', args.host or ''): raise ValueError('Supply --host VPS_HOST')
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', args.mac_user or ''): raise ValueError('Supply --mac-user YOUR_MAC_ACCOUNT')
    account = pwd.getpwnam(args.mac_user)
    if account.pw_uid < 501 or account.pw_shell in ('/usr/bin/false', '/sbin/nologin'): raise ValueError('Select a regular Mac account, not root')
    parent_key = public_key(args.public_key)
    host_key = public_key(args.host_key)
    for path in ('/Library', '/Library/Application Support', ROOT, '/Library/PrivilegedHelperTools', '/Library/LaunchDaemons'): safe_dir(path, 0o700 if path == ROOT else 0o755)
    if not Path('/Library/Application Support/Orbit/settings.json').is_file(): raise ValueError('Install and configure the Orbit agent first')
    # The helper is never bootstrapped from downloaded or unverified code.
    binary = Path('/Library/PrivilegedHelperTools/orbit-tunnel')
    temp = ROOT / 'helper.new'
    run('/usr/bin/xcrun', 'swiftc', '-O', str(SOURCE / 'Tunnel.swift'), '-o', str(temp))
    os.chmod(temp, 0o755); os.chown(temp, 0, 0)
    for label in ('com.side-forge.orbit.tunnel', 'com.side-forge.orbit.tunnel-sshd'):
        subprocess.run(['/bin/launchctl', 'bootout', 'system/' + label], capture_output=True)
    if subprocess.run(['/usr/bin/nc','-z','-w','1','127.0.0.1','2222'],capture_output=True).returncode == 0:
        raise ValueError('Local port 2222 is already in use; refusing to forward an unknown service')
    os.replace(temp, binary)
    for name in ('identity', 'host_key'):
        path = ROOT / name
        if path.is_symlink(): raise ValueError('Unsafe key path')
        if not path.exists(): run('/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(path))
        os.chmod(path, 0o600); os.chown(path, 0, 0)
    safe_dir('/private/etc/ssh')
    write('/private/etc/ssh/orbit-tunnel-parent-key', parent_key + '\n', 0o644)
    write(ROOT / 'known_hosts', 'orbit-tunnel-vps ' + host_key + '\n')
    write(ROOT / 'config.json', json.dumps(dict(host=args.host, port=args.port, user=args.tunnel_user, remotePort=args.remote_port)))
    ssh_config = mac_sshd_config(args.mac_user, ROOT)
    write(ROOT / 'sshd_config', ssh_config)
    run('/usr/sbin/sshd', '-t', '-f', str(ROOT / 'sshd_config'))
    import plistlib
    ssh_job = dict(Label='com.side-forge.orbit.tunnel-sshd', ProgramArguments=['/usr/sbin/sshd', '-D', '-e', '-f', str(ROOT / 'sshd_config')], RunAtLoad=True, KeepAlive=True, ThrottleInterval=15, StandardErrorPath='/var/log/orbit-tunnel-sshd.log')
    write('/Library/LaunchDaemons/com.side-forge.orbit.tunnel-sshd.plist', plistlib.dumps(ssh_job).decode(), 0o644)
    write('/Library/LaunchDaemons/com.side-forge.orbit.tunnel.plist', (SOURCE / 'com.side-forge.orbit.tunnel.plist').read_text(), 0o644)
    for label in ('com.side-forge.orbit.tunnel-sshd', 'com.side-forge.orbit.tunnel'):
        run('/bin/launchctl', 'bootstrap', 'system', '/Library/LaunchDaemons/' + label + '.plist')
    print('Mac configured. SSH access remains OFF until enabled in the dashboard.')
    print('Tunnel PUBLIC key for VPS setup:\n' + public_key(ROOT / 'identity.pub'))
    print('Mac host PUBLIC key to pin on your own computer:\n' + public_key(ROOT / 'host_key.pub'))
    print(f'Connect from your own computer after enabling: ssh -J YOUR_VPS_LOGIN@{args.host}:{args.port} -p {args.remote_port} -o HostKeyAlias=orbit-target-mac -o StrictHostKeyChecking=yes {args.mac_user}@127.0.0.1')

def server_sshd_config(user, port):
    return f'''Match User {user}
    AuthorizedKeysFile /etc/ssh/orbit-tunnel-keys/%u
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AllowTcpForwarding remote
    AllowStreamLocalForwarding no
    PermitListen 127.0.0.1:{port}
    PermitOpen none
    GatewayPorts no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTTY no
    PermitUserRC no
    MaxSessions 0
Match all
'''

def server(args):
    if platform.system() != 'Linux': raise ValueError('Run --server on the VPS')
    key = public_key(args.public_key)
    sshd = shutil.which('sshd') or '/usr/sbin/sshd'
    run(sshd, '-t')
    for path in ('/etc', '/etc/ssh', '/etc/ssh/sshd_config.d'): safe_dir(path)
    user = args.tunnel_user
    try:
        account = pwd.getpwnam(user)
        # Refuse to repurpose an existing account not created by this installer.
        if account.pw_gecos != 'Orbit restricted tunnel': raise ValueError('Existing account is not an Orbit tunnel account')
    except KeyError:
        run('/usr/sbin/useradd', '--system', '--no-create-home', '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', '--comment', 'Orbit restricted tunnel', user)
        # '*' is an impossible password hash, not a locked account; keys work with or without PAM.
        run('/usr/sbin/usermod', '--password', '*', user)
    keys = Path('/etc/ssh/orbit-tunnel-keys'); safe_dir(keys); os.chmod(keys, 0o755)
    write(keys / user, f'restrict,port-forwarding,permitlisten="127.0.0.1:{args.remote_port}" {key}\n', 0o644)
    config = server_sshd_config(user, args.remote_port)
    # Use an explicit top-of-file include so an existing Match cannot swallow it.
    main = Path('/etc/ssh/sshd_config'); original = main.read_text()
    include = f'Include /etc/ssh/orbit-tunnel-{user}.conf\n'
    target = Path(f'/etc/ssh/orbit-tunnel-{user}.conf'); old = target.read_text() if target.exists() else None
    try:
        write(target, config, 0o600)
        if not original.startswith(include): write(main, include + original, 0o600)
        run(sshd, '-t')
        effective = run(sshd, '-T', '-C', f'user={user},host=localhost,addr=127.0.0.1')
        for expected in ('gatewayports no', 'allowtcpforwarding remote', 'passwordauthentication no', 'kbdinteractiveauthentication no', 'maxsessions 0', f'permitlisten 127.0.0.1:{args.remote_port}'):
            if expected not in effective.splitlines(): raise ValueError('Unsafe effective SSH configuration: ' + expected)
        run('systemctl', 'reload', 'ssh' if subprocess.run(['systemctl', 'is-active', '--quiet', 'ssh']).returncode == 0 else 'sshd')
    except Exception:
        write(main, original, 0o600)
        if old is None: target.unlink(missing_ok=True)
        else: write(target, old)
        raise
    print('VPS restricted tunnel account configured; its forwarded port is private to this VPS.')
    print('Verified VPS host PUBLIC key for Mac setup:\n' + public_key('/etc/ssh/ssh_host_ed25519_key.pub'))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True); mode.add_argument('--mac', action='store_true'); mode.add_argument('--server', action='store_true')
    parser.add_argument('--host'); parser.add_argument('--port', type=int, default=22)
    parser.add_argument('--remote-port', type=int, default=22001)
    parser.add_argument('--tunnel-user', default='orbit-tunnel'); parser.add_argument('--mac-user')
    parser.add_argument('--public-key', required=True, help='Parent public key on Mac; tunnel public key on VPS')
    parser.add_argument('--host-key', help='VPS host public key, obtained through a trusted VPS login')
    args = parser.parse_args()
    try:
        if os.geteuid() != 0: raise ValueError('Run using sudo on the machine being configured')
        if not 1 <= args.port <= 65535 or not 1024 <= args.remote_port <= 65535: raise ValueError('Invalid port')
        if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', args.tunnel_user): raise ValueError('Invalid tunnel account')
        if args.mac and not args.host_key: raise ValueError('Supply --host-key with the verified VPS public host key')
        (mac if args.mac else server)(args)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        sys.exit('Setup failed: ' + str(error))
