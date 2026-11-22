#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ ${1:-} == --cli || -n ${SSH_CONNECTION:-} || -n ${SSH_TTY:-} ]]; then
  if [[ ${1:-} == --cli ]]; then shift; fi
  if (( EUID == 0 )); then
    exec ./OrbitSetup --install-cli "$PWD/Orbit.pkg" "$@"
  else
    exec /usr/bin/sudo ./OrbitSetup --install-cli "$PWD/Orbit.pkg" "$@"
  fi
fi
if (( $# > 0 )); then
  echo 'For terminal setup use: bash "Install Orbit.command" --cli --user TARGET_MAC_USERNAME [--credentials-stdin]' >&2
  exit 2
fi
echo 'Orbit installs app blocking, foreground tracking and Chrome policy setup.'
echo 'Existing saved settings are reused. For missing settings, have the VPS DEVICE, ACTIVITY and BROWSER tokens and published Chrome Web Store extension ID ready. macOS will request administrator authorization.'
./OrbitSetup --install "$PWD/Orbit.pkg" || {
  echo 'Installation did not complete. Review the error above.'
  read -rp 'Press Enter to close. ' _
  exit 1
}
