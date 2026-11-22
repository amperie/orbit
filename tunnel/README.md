# Private remote SSH access

This feature is opt-in. Installing the normal Orbit agent does **not** enable SSH.
The dashboard's **Settings → Remote SSH access** controls a separate helper.
New Macs remain off after provisioning and check-in until an administrator enables
access. Each enable request lasts **one hour**, measured from the web request,
not from connection time. The helper reconnects after reboot, wake, or network
loss only during the remaining window; reconnecting never resets the deadline.
After a helper restart it must contact the server before opening the tunnel.

An independent local watchdog closes forwarding at expiry even if control-server
requests stall or fail. Its clock includes time spent asleep. The previous
unbounded local cache is ignored; old persistent requests fail closed until an
administrator issues a new one-hour request. Deploy both the updated server and
helper to enforce these rules.

Turn off cancels access at the next successful control check (normally about five
seconds). An offline Mac cannot receive an early off request, but the original
one-hour deadline still applies. Closing the tunnel also closes its SSH sessions.

The UI shows the requested window and remaining minutes separately from the
helper's reported state: connected, connecting, closed, or setup error. Reports
older than 40 seconds become **unknown**, including when refreshes fail. An expired
request does not count as confirmed closure until the helper reports it.

## Security model

- Your personal Ed25519 SSH key authenticates to one specified Mac account.
  Password, keyboard-interactive and root login are disabled. Your private key
  stays on your own computer. Losing it requires running Mac setup again.
- A separate key created on the target Mac authenticates the tunnel to a dedicated
  VPS account. That account cannot open shell sessions, execute commands, forward
  agents, open local forwards or expose the reverse port publicly.
- The VPS only binds `127.0.0.1:22001`. Reach it through your existing, authenticated
  VPS login using ProxyJump. The restricted tunnel account cannot be that login.
- The Mac runs a dedicated SSH server on `127.0.0.1:2222`. General macOS Remote
  Login is not enabled or changed. The listener stays local while remote access
  is off. Existing Remote Login, if already enabled, remains independently active.
- Both SSH server identities must be pinned. Never skip host-key verification.
- Local provisioning fixes the destination and keys. The web API only accepts
  enable/disable with an optimistic revision; device credentials cannot enable
  access. Administrator credentials alone are insufficient to log into the Mac.
- Key files, helper settings and the control socket are root protected. The helper
  refuses insecure permissions, HTTP servers and authentication redirects.
- The current device credential is shared by Mac agents: possession can forge
  helper status or read enable requests. It cannot change requests or bypass the
  Mac's SSH authentication. Keep it protected; per-device enrollment is future work.

## One-time setup

Requires the configured Orbit agent on the target Mac, Apple's command-line tools,
Python 3, and an existing administrator SSH login to your Linux VPS with OpenSSH
and systemd. Deploy the updated four server files first. No additional public port
or firewall opening is needed.

1. On your own computer, use an existing Ed25519 SSH key or create one with
   `ssh-keygen -t ed25519`. Copy **only its `.pub` file** to the target Mac as
   `parent.pub`. Through your trusted VPS console/login, obtain
   `/etc/ssh/ssh_host_ed25519_key.pub` and verify its fingerprint. Copy that public
   file to the target Mac as `vps-host.pub`.
2. From this repository on the **target Mac**, run:

   ```sh
   sudo python3 tunnel/setup.py --mac --host VPS_HOST --mac-user YOUR_MAC_ACCOUNT --public-key parent.pub --host-key vps-host.pub
   ```

   This compiles the helper, creates the tunnel key, installs the two LaunchDaemons
   and prints public keys. Copy its **tunnel public key** into `mac-tunnel.pub` on
   the VPS. Save its **Mac host public key** on your own computer.
3. From this repository on the **VPS**, run:

   ```sh
   sudo python3 tunnel/setup.py --server --public-key mac-tunnel.pub
   ```

   Setup validates sshd before reloading and restores its config on validation or
   reload failure. Keep your existing VPS session open until verified. This adds
   a restricted system account; it does not change your normal VPS account.
4. On your own computer, add the Mac host public key to your SSH `known_hosts`
   with the name `orbit-target-mac` (line format:
   `orbit-target-mac ssh-ed25519 PUBLIC_KEY_BASE64`). In Orbit Settings, refresh
   remote access, enable it, and wait for **Tunnel connected**. Then connect:

   ```sh
   ssh -J YOUR_VPS_LOGIN@VPS_HOST -p 22001 -o HostKeyAlias=orbit-target-mac -o StrictHostKeyChecking=yes YOUR_MAC_ACCOUNT@127.0.0.1
   ```

   Add `-i /path/to/your/personal/key` if it is not your default SSH identity.
   The jump host uses your normal VPS SSH configuration and trusted host key.

For a nonstandard VPS SSH port, pass `--port PORT` on Mac setup and use
`-J YOUR_VPS_LOGIN@VPS_HOST:PORT`. For multiple Macs, use a distinct
`--tunnel-user` and `--remote-port` on both setup commands for each Mac; use a
separate Mac host alias on your own computer. Choose an unused reverse port.
The target Mac's local listener uses port 2222, which must be free.

## Operations and removal

Status and requests are deliberately shown separately. A pending disable is not
proof the tunnel is already closed. Fresh helper status is required to enable
access; an off request is accepted even when a Mac is offline. Access turns off automatically after one hour, or earlier when explicitly disabled. SSH connections and authentication attempts are
logged by the dedicated Mac sshd; enable/disable requests also appear in the
dashboard’s policy and connection alerts.

Check `/var/log/orbit-tunnel.log` and `/var/log/orbit-tunnel-sshd.log` for startup
errors. The server has no private SSH key. The Mac helper doesn't auto-update with
the main agent; rerun setup from reviewed source when updating it.

The updated Orbit uninstaller stops and removes both tunnel daemons, the helper,
and the dedicated authorized-key file. It preserves the root-only tunnel directory
and keys to avoid silently losing pinned identities. To remove those too, after
uninstalling: `sudo rm -rf '/Library/Application Support/OrbitTunnel'`.
On the VPS, remove the matching `Include /etc/ssh/orbit-tunnel-USER.conf` line,
the included file, `/etc/ssh/orbit-tunnel-keys/USER`, and the dedicated account;
validate with `sudo sshd -t` before reloading SSH. Never remove your normal login.
