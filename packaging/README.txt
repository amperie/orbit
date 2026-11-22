Orbit installer — macOS 13 or later, Intel or Apple Silicon

1. Log into the Mac account whose foreground app usage should be tracked.
2. Extract the whole ZIP. Keep all files together.
3. Open Install Orbit.command. It prompts privately for the VPS DEVICE and
   ACTIVITY and distinct read-only BROWSER tokens, plus the published Chrome
   Web Store extension ID (32 letters). It then requests an administrator username/password through
   macOS. A standard user can authorize with a separate administrator account.
4. Approve Orbit Chrome Browser Policy in System Settings > General > Device
   Management with administrator credentials. Restart Chrome and verify
   chrome://policy. This system profile force-installs Orbit across Chrome
   profiles and disables Guest and Incognito. Test a blocked site in a new
   Chrome profile. Website blocking is pending until approval and verification.
5. Open https://orbit.side-forge.com and sign in with your ADMIN token.
   Confirm the blocker and monitor connect; test Roblox blocking and a reboot.


Terminal / SSH installation (no graphical dialogs):
  Extract the whole installer ZIP, then run on the target Mac:
    cd /path/to/Orbit-Installer
    bash "Install Orbit.command" --cli --user TARGET_MAC_USERNAME

  Use an administrator SSH login with sudo access. For interactive setup, connect
  using ssh -t so sudo and hidden token prompts have a terminal. --user selects
  the account whose activity is tracked; it can differ from your SSH login.
  SSH sessions automatically select CLI mode, but specifying --cli is clearer.
  Existing valid settings are reused. Only missing tokens/extension ID prompt.
  Only one SSH install runs at a time; another attempt fails immediately.
  The selected account must exist and its home must be available and writable.
  No AppleScript, System Settings, web browser or other windows are opened.

  If the selected user is logged out, the blocking daemon starts immediately
  and the foreground tracker is configured to start at their next desktop login.
  If their desktop is active, the tracker starts immediately.

  Fully noninteractive mode (sudo must already be authorized):
    sudo -n ./OrbitSetup --install-cli ./Orbit.pkg --user TARGET_MAC_USERNAME --credentials-stdin < /secure/path/credentials.json

  The JSON object may contain serverURL, deviceToken, activityToken,
  browserToken and extensionID. Saved values fill omitted fields. Missing or
  invalid required fields cause a failure before services/binaries are changed.
  DEVICE, ACTIVITY and BROWSER tokens must all be distinct. Supply credentials
  through standard input, never as command arguments. Protect the JSON file
  with chmod 600 and delete it after setup if it is no longer needed.

  First-time Chrome policy activation still requires local administrator
  approval or deployment through MDM. Existing approved policies are preserved.
  The CLI generates the profile in the selected user's Orbit settings directory,
  reports pending approval, and finishes without trying to open the desktop.
  Rotating the browser token also requires updating the approved policy.
  SSH tunnel provisioning remains a separate opt-in setup.

No Git, Python, Xcode or compiler is needed on the target Mac. The package
contains no credentials. Credentials are stored privately on the installed Mac.
The blocking daemon runs system-wide; tracking runs only for the chosen user.
Re-run the setup launcher to update binaries. After administrator authorization,
it reuses valid saved device credentials and matching user monitor/Chrome settings.
Only missing or invalid values are requested. Chrome profile approval may still
be required. Saved credentials are format-checked, not tested against the VPS;
if you rotated a token on the VPS, update the corresponding saved settings first.

This initial release is NOT Apple Developer signed or notarized. macOS may
block the launcher/package. If you trust the download, use the relevant
Privacy & Security approval in System Settings. Do not disable Gatekeeper.
An organization-managed Mac may prohibit unsigned software entirely.

Opening Orbit.pkg directly only installs files. Use Install Orbit.command (desktop
or --cli mode) to
configure credentials and start services. Closing the installer does not stop
the installed services; they persist across reboots and logins.

Chrome downloads the published extension after profile approval. The extension
must already be published in the Chrome Web Store; an unpacked ID will not work.
The package does not install Safari extensions, auto-update the Mac, or make
the user-owned tracker tamper-resistant.

Uninstall:
  Open Uninstall Orbit.command from this bundle, choose Keep local data or
  Delete local data, and authorize with administrator credentials. It removes
  the blocker and trackers for all local users, including source-installed
  trackers. It works with earlier Orbit package versions as well. VPS history
  is unchanged. It attempts removal of the Orbit Chrome system profile, which
  releases its extension and Guest/Incognito policies. If macOS refuses removal,
  System Settings opens for manual removal; MDM profiles require MDM removal.
  Restart Chrome and remove Orbit at chrome://extensions if it remains. Other
  Chrome policies and browsing data are preserved. Safari is unchanged.
  Empty settings folders may remain.
  After installation you can also run:
    /usr/local/libexec/orbit-uninstall --prompt
  Keep local data preserves credentials, policy cache, telemetry queues and
  logs. Delete local data removes these known files. Other files are preserved.

Troubleshooting:
  sudo launchctl print system/com.side-forge.orbit.agent
  launchctl print gui/$(id -u)/com.side-forge.orbit.foreground
  sudo tail -n 50 /var/log/orbit.log

Signed automatic updates:
  The package includes an updater for the agent and bundled monitor only.
  It checks hourly when a release-signing public key has been provisioned;
  builds without a key leave automatic updates disabled. Update settings and
  anti-rollback state are preserved through reinstalls and uninstall. See
  updater/README.md in the repository for enrollment and required real-Mac tests.
