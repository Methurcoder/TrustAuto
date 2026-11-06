#!/bin/bash
# Caches packages that a removal would pull in as replacements, because the containers have no network.
grep "^remove " rerun.txt | while read -r _ p; do
  apt-get -s --allow-remove-essential remove "$p" 2>/dev/null | awk "/^Inst /{print \$2}"
done | sort -u > replacements.txt
wc -l replacements.txt
xargs -a replacements.txt apt-get -y --download-only --reinstall install >/dev/null 2>fetch.err || true
for p in $(cat replacements.txt); do
  ls /var/cache/apt/archives/${p}_*.deb >/dev/null 2>&1 || (cd /var/cache/apt/archives && apt-get download "$p" >/dev/null 2>>fetch.err)
done
ls /var/cache/apt/archives/*.deb | wc -l
du -sh /var/cache/apt/archives
