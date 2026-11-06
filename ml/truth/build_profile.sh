#!/bin/bash
# Builds a machine image for truth_lab.py. Run as root in the disposable lab VM only.
#   build_profile.sh NAME debian|ubuntu SUITE "ROLES" PACKAGES...
set -eu
name=$1 distro=$2 suite=$3 roles=$4; shift 4
extra=$(IFS=,; echo "$*")
dir=/var/lib/ta-truth/profiles/$name
mkdir -p "$dir"
case $distro in
  debian) mirror=http://deb.debian.org/debian comps=main keyring=/usr/share/keyrings/debian-archive-keyring.gpg ;;
  ubuntu) mirror=http://ports.ubuntu.com/ubuntu-ports comps=main,universe keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg ;;
esac
rm -rf "$dir/rootfs"
# Paths in hooks must not pass through absolute symlinks, which would lead out of the image.
# Docs are left out only to save disk. No service reads them.
mmdebstrap --variant=important --components="$comps" --keyring="$keyring" \
  --include="systemd,systemd-sysv,dbus,openssh-server,sudo,apt,iproute2,python3,$extra" \
  --dpkgopt='path-exclude=/usr/share/doc/*' --dpkgopt='path-include=/usr/share/doc/*/copyright' \
  --dpkgopt='path-exclude=/usr/share/man/*' --dpkgopt='path-exclude=/usr/share/locale/*' \
  --skip=cleanup/apt/lists \
  --setup-hook='mkdir -p "$1/usr/share/man/man1"' \
  --essential-hook='echo "postfix postfix/main_mailer_type select Internet Site" | chroot "$1" debconf-set-selections; echo "postfix postfix/mailname string truth.test" | chroot "$1" debconf-set-selections; echo "slapd slapd/no_configuration boolean false" | chroot "$1" debconf-set-selections; echo "slapd slapd/domain string truth.test" | chroot "$1" debconf-set-selections' \
  --customize-hook='echo truth-'"$name"' > "$1/etc/hostname"' \
  --customize-hook='touch "$1/var/lib/dpkg/available"' \
  --customize-hook='ssh-keygen -q -A -f "$1" || true' \
  --customize-hook='if [ -e "$1/usr/lib/systemd/system/nmbd.service" ]; then ln -sf /dev/null "$1/etc/systemd/system/nmbd.service"; fi' \
  --customize-hook='if [ -d "$1/var/www/html" ]; then printf "<?php echo \"php-\" . \"works\"; ?>\n" > "$1/var/www/html/probe.php"; fi' \
  --customize-hook='if [ -e "$1/etc/nginx/sites-available/default" ]; then printf "server {\n listen 80 default_server;\n root /var/www/html;\n location ~ \\.php\$ { include snippets/fastcgi-php.conf; fastcgi_pass unix:/run/php/php-fpm.sock; }\n}\n" > "$1/etc/nginx/sites-available/default"; fi' \
  --customize-hook='sed -i "s/^port = .*/port = 5432/" "$1"/etc/postgresql/*/main/postgresql.conf 2>/dev/null || true' \
  "$suite" "$dir/rootfs" "$mirror"
echo "$roles" > "$dir/roles.txt"
du -sh "$dir/rootfs"
