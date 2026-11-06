#!/bin/bash
# Stops the lab VM from sending anything out while corpus commands run. Run as root in the lab VM only.
#   lab_firewall.sh on GATEWAY_IP   keeps only replies on the SSH connection from that address
#   lab_firewall.sh off
set -eu
case ${1:-} in
  on)
    nft -f - <<RULES
table inet ta_lab_guard
delete table inet ta_lab_guard
table inet ta_lab_guard {
  chain guard_output {
    type filter hook output priority 0; policy drop;
    oif lo accept
    ip daddr ${2:?gateway} tcp sport 22 ct state established accept
    # Renewing the VM's own address, or a long run would lose its SSH connection.
    udp sport 68 udp dport 67 accept
  }
  chain guard_forward {
    type filter hook forward priority 0; policy drop;
  }
}
RULES
    # Proves it took effect: an outside address must now be unreachable.
    if curl -s --max-time 5 -o /dev/null http://deb.debian.org/; then
      nft delete table inet ta_lab_guard
      echo "firewall did not stop traffic" >&2
      exit 1
    fi
    echo on
    ;;
  off)
    nft delete table inet ta_lab_guard 2>/dev/null || true
    echo off
    ;;
  *) exit 2 ;;
esac
