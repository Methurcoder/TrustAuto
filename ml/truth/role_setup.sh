#!/bin/bash
# Turns the lab VM into a different machine: a server with roles the first run never saw.
set -u
cd ~bmoperator/truth
dpkg-query -W -f='${Package}\n' | sort > pkgs_before.txt
systemctl list-unit-files --type=service --no-legend | awk '{print $1}' | sed 's/\.service$//' | sort -u > units_before.txt
export DEBIAN_FRONTEND=noninteractive
apt-get install -y --no-install-recommends nginx postgresql mariadb-server redis-server docker.io network-manager samba bind9 haproxy openvpn ufw fail2ban nfs-kernel-server avahi-daemon chrony apparmor-utils > role_install.log 2>&1
echo "install rc $?"
dpkg-query -W -f='${Package}\n' | sort > pkgs_after.txt
systemctl list-unit-files --type=service --no-legend | awk '{print $1}' | sed 's/\.service$//' | grep -v '@$' | sort -u > units_after.txt
comm -13 pkgs_before.txt pkgs_after.txt > new_pkgs.txt
comm -13 units_before.txt units_after.txt > new_units.txt
wc -l new_pkgs.txt new_units.txt
sed 's/^/remove /' new_pkgs.txt > cases_fresh.txt
sed 's/^/stop /' new_units.txt >> cases_fresh.txt
sed 's/^/restart /' new_units.txt >> cases_fresh.txt
wc -l cases_fresh.txt
cp /var/lib/dpkg/status dpkg_status_fresh.txt
cp units.txt units_first.txt; cp new_units.txt units.txt
python3 collect_facts.py; mv facts.json facts_fresh.json; cp units_first.txt units.txt
# The shared layer hides later changes to /etc/passwd, so build it again.
umount -l /run/ta-truth-golden 2>/dev/null; rm -rf /run/ta-truth-golden
df -h / | tail -1
