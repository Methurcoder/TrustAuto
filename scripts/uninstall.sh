#!/usr/bin/env bash
# Removes TrustAuto. Keeps the policy and audit log unless --purge is given.
set -euo pipefail

[[ "$(uname -s)" == Linux ]] || { echo "Linux only" >&2; exit 1; }
[[ "$EUID" -eq 0 ]] || { echo "run as root" >&2; exit 1; }

# The setuid binary goes first, so elevation stops before anything else changes.
rm -f /usr/lib/trustauto/trustauto-broker /usr/lib/trustauto/trustauto-broker.new
rm -f /usr/local/bin/trustauto /etc/pam.d/trustauto
if [[ -d /run/systemd/system ]]; then
  systemctl disable --now trustauto-facts.timer >/dev/null 2>&1 || true
fi
rm -f /etc/systemd/system/trustauto-facts.service /etc/systemd/system/trustauto-facts.timer
rm -f /etc/apt/apt.conf.d/80trustauto-facts /usr/lib/trustauto/trustauto-facts
[[ -d /run/systemd/system ]] && systemctl daemon-reload || true
rm -rf /var/lib/trustauto
rmdir /usr/lib/trustauto 2>/dev/null || true

if [[ "${1:-}" == --purge ]]; then
  rm -rf /etc/trustauto /var/log/trustauto
fi
getent group trustauto >/dev/null && groupdel trustauto || true

echo "TrustAuto removed. Remove the shell-init line from your shell rc files."
