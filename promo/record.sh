#!/bin/bash
# Runs on the disposable lab VM only: installs, records, removes.
set -uo pipefail
cd ~bmoperator/TrustAuto
U=ta_demo
[[ ! -e /etc/trustauto ]] || { echo already installed; exit 1; }
trap 'scripts/uninstall.sh --purge >/dev/null 2>&1; userdel -r $U >/dev/null 2>&1' EXIT
scripts/install.sh target/release >/dev/null
sed -i 's/^approvers = \[\]/approvers = ["ta_demo"]/' /etc/trustauto/policy.toml
useradd -m -s /bin/bash -G trustauto $U
echo "$U:$(head -c 24 /dev/urandom | base64)" | chpasswd
cat > /home/$U/.demorc <<'RC'
eval "$(trustauto shell-init bash)"
PS1='$ '
RC
chown $U: /home/$U/.demorc
ls -l target/release/trustauto
python3 /tmp/ta_record.py /tmp/ta_demo.jsonl $U
echo rc=$?
