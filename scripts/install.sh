#!/usr/bin/env bash
# Installs TrustAuto on Linux. Adds nobody to the trustauto group: that stays
# an explicit decision for the operator, because membership grants what the
# policy allows.
#
#   sudo scripts/install.sh [DIR_WITH_BINARIES]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="${1:-$ROOT/target/release}"

[[ "$(uname -s)" == Linux ]] || { echo "Linux only" >&2; exit 1; }
[[ "$EUID" -eq 0 ]] || { echo "run as root" >&2; exit 1; }
for f in trustauto trustauto-broker trustauto-facts; do
  [[ -x "$BIN_DIR/$f" ]] || { echo "missing $BIN_DIR/$f (cargo build --release)" >&2; exit 1; }
done

getent group trustauto >/dev/null || groupadd --system trustauto

# Installed with no setuid bit first, so a half-finished install grants nothing.
install -d -o root -g root -m 0755 /usr/lib/trustauto
install -o root -g trustauto -m 0750 "$BIN_DIR/trustauto-broker" /usr/lib/trustauto/trustauto-broker.new
chmod 4750 /usr/lib/trustauto/trustauto-broker.new
mv -f /usr/lib/trustauto/trustauto-broker.new /usr/lib/trustauto/trustauto-broker
install -o root -g root -m 0755 "$BIN_DIR/trustauto" /usr/local/bin/trustauto
install -o root -g root -m 0755 "$BIN_DIR/trustauto-facts" /usr/lib/trustauto/trustauto-facts

install -d -o root -g root -m 0755 /etc/trustauto
if [[ ! -e /etc/trustauto/policy.toml ]]; then
  install -o root -g root -m 0644 "$ROOT/config/policy.toml" /etc/trustauto/policy.toml
fi
install -o root -g root -m 0644 "$ROOT/config/pam.d-trustauto" /etc/pam.d/trustauto

# Machine facts for the risk model (hybrid and ml modes). Rule mode never reads them.
install -d -o root -g root -m 0755 /var/lib/trustauto
if [[ -d /run/systemd/system ]]; then
  install -o root -g root -m 0644 "$ROOT/config/trustauto-facts.service" /etc/systemd/system/trustauto-facts.service
  install -o root -g root -m 0644 "$ROOT/config/trustauto-facts.timer" /etc/systemd/system/trustauto-facts.timer
  systemctl daemon-reload
  systemctl enable --now trustauto-facts.timer >/dev/null
fi
if [[ -d /etc/apt/apt.conf.d ]]; then
  install -o root -g root -m 0644 "$ROOT/config/apt-80trustauto-facts" /etc/apt/apt.conf.d/80trustauto-facts
fi
echo "Collecting machine facts (a minute or two)..."
/usr/lib/trustauto/trustauto-facts collect || echo "warning: fact collection failed; hybrid and ml modes will ask an approver" >&2

log_group=root
getent group adm >/dev/null && log_group=adm
install -d -o root -g "$log_group" -m 0750 /var/log/trustauto
touch /var/log/trustauto/audit.jsonl
chown root:"$log_group" /var/log/trustauto/audit.jsonl
chmod 0640 /var/log/trustauto/audit.jsonl

cat <<'EOF'
TrustAuto installed.

Next steps:
  1. Edit /etc/trustauto/policy.toml and set approval.approvers
  2. trustauto check
  3. sudo usermod -aG trustauto USER     (then log in again)
  4. Add to ~/.bashrc or ~/.zshrc:
       eval "$(trustauto shell-init bash)"   # or zsh
  5. The mode is hybrid (rules and ML). To change it:
       sudo trustauto mode rule    (rules only)
       sudo trustauto mode ml      (ML only, preview, high risk)
EOF
