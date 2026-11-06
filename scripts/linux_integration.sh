#!/usr/bin/env bash
# End-to-end checks of the setuid boundary. These cannot run on macOS or in unit
# tests, because they need a real setuid binary, PAM and multiple users.
#
# It installs a setuid binary and creates temporary accounts with passwords, so
# run it only in a disposable VM (take a snapshot or clone first):
#
#   cargo build --release
#   sudo TRUSTAUTO_TEST_DISPOSABLE=yes scripts/linux_integration.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="${1:-$ROOT/target/release}"
BROKER=/usr/lib/trustauto/trustauto-broker
POLICY=/etc/trustauto/policy.toml
AUDIT=/var/log/trustauto/audit.jsonl
PROBE=/usr/local/bin/ta-probe
SPROBE=/usr/local/sbin/ta-sprobe
# A real file under a deny rule. System tools can't serve here: on Ubuntu 26.04
# `rm` is a symlink to gnurm, which the alias check refuses before any rule runs.
DENIED=/usr/local/bin/ta-denied
MEMBER=ta_member
OUTSIDER=ta_outsider
APPROVER=ta_approver
WORK="$(mktemp -d /tmp/trustauto-test.XXXXXX)"
chmod 755 "$WORK"

[[ "$(uname -s)" == Linux ]] || { echo "Linux only" >&2; exit 1; }
[[ "$EUID" -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ "${TRUSTAUTO_TEST_DISPOSABLE:-}" == yes ]] || {
  echo "This installs a setuid binary and temporary accounts." >&2
  echo "Set TRUSTAUTO_TEST_DISPOSABLE=yes inside a disposable VM." >&2
  exit 1
}
[[ ! -e /etc/trustauto && ! -e "$BROKER" ]] || {
  echo "An existing TrustAuto install is present; refusing to overwrite it." >&2
  exit 1
}
for tool in runuser python3 getent; do
  command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 1; }
done

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); echo "  ok    $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL  $1"; [[ -n "${2:-}" ]] && printf '        %s\n' "$2"; }
section() { echo; echo "== $1"; }

cleanup() {
  chattr -i "$AUDIT" 2>/dev/null
  [[ -e /var/log/trustauto.moved ]] && { rm -rf /var/log/trustauto; mv /var/log/trustauto.moved /var/log/trustauto; }
  "$ROOT/scripts/uninstall.sh" --purge >/dev/null 2>&1
  rm -f "$PROBE" "$SPROBE" "$DENIED"
  for u in "$MEMBER" "$OUTSIDER" "$APPROVER"; do userdel -r "$u" >/dev/null 2>&1; done
  rm -rf "$WORK"
}
trap cleanup EXIT

as() { # as USER COMMAND... : run with a clean, predictable user environment
  local who="$1"; shift
  runuser -u "$who" -- env -i PATH=/usr/bin:/bin HOME="/home/$who" USER="$who" "$@"
}

expect_rc() { # NAME EXPECTED ACTUAL OUTPUT
  if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1" "exit $3, wanted $2: $4"; fi
}
expect_has() { # NAME NEEDLE HAYSTACK
  if grep -qF -- "$2" <<<"$3"; then pass "$1"; else fail "$1" "missing [$2] in: $3"; fi
}
expect_not() { # NAME NEEDLE HAYSTACK
  if grep -qF -- "$2" <<<"$3"; then fail "$1" "found [$2] in: $3"; else pass "$1"; fi
}

write_policy() { # MODE REQUIRE_TTY
  cat >"$POLICY" <<EOF
version = 1
mode = "$1"
require_tty = $2

[approval]
approvers = ["$APPROVER"]
attempts = 2

[[rule]]
id = "probe"
action = "allow"
bin = "$PROBE"
args = []

[[rule]]
id = "probe-word"
action = "allow"
bin = "$PROBE"
args = ["echo", "{word}"]

[[rule]]
id = "probe-ceiling"
action = "envelope"
bin = "$PROBE"
args = ["ceiling"]

[[rule]]
id = "probe-ask"
action = "ask"
bin = "$PROBE"
args = ["ask-me"]

[[rule]]
id = "sprobe"
action = "allow"
bin = "$SPROBE"
args = []

[[rule]]
id = "id-as-user"
action = "user"
bin = "/usr/bin/id"
args = ["{any}*"]

[[rule]]
id = "no-denied"
action = "deny"
bin = "$DENIED"
args = ["{any}*"]
EOF
  chown root:root "$POLICY"
  chmod 0644 "$POLICY"
}

section "setup"
"$ROOT/scripts/install.sh" "$BIN_DIR" >/dev/null || { echo "install failed" >&2; exit 1; }
PASSWORD="$(head -c 24 /dev/urandom | base64 | tr -d '/+=')"
export PASSWORD
for u in "$MEMBER" "$OUTSIDER" "$APPROVER"; do useradd -m -s /bin/bash "$u" || exit 1; done
usermod -aG trustauto "$MEMBER"
usermod -aG trustauto "$APPROVER"
printf '%s:%s\n' "$APPROVER" "$PASSWORD" | chpasswd || exit 1
printf '%s:%s\n' "$MEMBER" "$PASSWORD" | chpasswd || exit 1

cat >"$PROBE" <<'EOF'
#!/bin/sh
echo "euid=$(id -u) ruid=$(id -ru) gid=$(id -g) groups=$(id -G)"
echo "cwd=$(pwd)"
echo "args=$*"
echo "fsize=$(ulimit -f)"
echo "fds=$(ls /proc/self/fd | tr '\n' ' ')"
env | sort | sed 's/^/env:/'
EOF
chmod 0755 "$PROBE"
cp "$PROBE" "$SPROBE"
printf '#!/bin/sh\nrm -f "$1"\n' >"$DENIED"
chmod 0755 "$DENIED"
write_policy rule false
pass "installed into the system"

section "installation"
mode="$(stat -c '%a %U %G' "$BROKER")"
expect_has "broker is 4750 root:trustauto" "4750 root trustauto" "$mode"
expect_has "cli is not setuid" "755 root" "$(stat -c '%a %U' /usr/local/bin/trustauto)"
out="$(as "$MEMBER" /usr/local/bin/trustauto check 2>&1)"; rc=$?
expect_rc "policy validates" 0 "$rc" "$out"

section "automatic elevation"
out="$(as "$MEMBER" "$BROKER" run -- ta-probe </dev/null 2>&1)"; rc=$?
expect_rc "allowed command runs" 0 "$rc" "$out"
expect_has "runs as root" "euid=0 ruid=0 gid=0" "$out"
expect_has "supplementary groups are root only" "groups=0" "$out"
expect_has "cwd is reset" "cwd=/" "$out"

out="$(as "$MEMBER" "$BROKER" run -- ta-probe echo hello </dev/null 2>&1)"; rc=$?
expect_rc "typed argument accepted" 0 "$rc" "$out"
out="$(as "$MEMBER" "$BROKER" run -- ta-probe echo --evil </dev/null 2>&1)"; rc=$?
expect_rc "option injection into a typed argument refused" 126 "$rc" "$out"
expect_not "refused command did not run" "euid=" "$out"

section "environment and inherited state"
out="$(runuser -u "$MEMBER" -- env -i PATH=/usr/bin:/bin FOO=leak PYTHONPATH=/tmp/x BASH_ENV=/tmp/x \
  LD_PRELOAD=/tmp/x.so LD_LIBRARY_PATH=/tmp IFS=x PAGER=/tmp/evil EDITOR=/tmp/evil TERM='xterm;id' \
  LANG=C.UTF-8 "$BROKER" run -- ta-probe </dev/null 2>&1)"
for needle in env:FOO env:PYTHONPATH env:BASH_ENV env:LD_PRELOAD env:LD_LIBRARY_PATH /tmp/evil 'env:TERM='; do
  expect_not "scrubbed $needle" "$needle" "$out"
done
expect_has "secure PATH" "env:PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" "$out"
expect_has "root HOME" "env:HOME=/root" "$out"
expect_has "pager neutralized" "env:PAGER=cat" "$out"
expect_has "locale kept when valid" "env:LANG=C.UTF-8" "$out"
expect_has "caller recorded for the child" "env:TRUSTAUTO_USER=$MEMBER" "$out"

out="$(runuser -u "$MEMBER" -- bash -c "exec 9</etc/hostname; exec 42</etc/hostname; PATH=/usr/bin:/bin exec $BROKER run -- ta-probe" </dev/null 2>&1)"
fds="$(grep '^fds=' <<<"$out")"
expect_not "inherited fd 9 closed" " 9 " "$fds"
expect_not "inherited fd 42 closed" " 42 " "$fds"

out="$(runuser -u "$MEMBER" -- bash -c "ulimit -f 1; exec $BROKER run -- ta-probe" </dev/null 2>&1)"
expect_has "RLIMIT_FSIZE reset" "fsize=unlimited" "$out"

mkdir -p "$WORK/evil"
printf '#!/bin/sh\necho HIJACKED\n' >"$WORK/evil/ta-probe"
chmod 755 "$WORK/evil/ta-probe"
out="$(runuser -u "$MEMBER" -- env -i PATH="$WORK/evil:/usr/bin:/bin" "$BROKER" run -- ta-probe </dev/null 2>&1)"
expect_not "caller PATH cannot hijack the binary" "HIJACKED" "$out"
expect_has "the real binary still ran" "euid=0" "$out"

section "binary resolution"
out="$(as "$MEMBER" "$BROKER" run -- "$WORK/evil/ta-probe" </dev/null 2>&1)"; rc=$?
expect_rc "user-writable binary refused" 126 "$rc" "$out"
expect_not "user-writable binary did not run" "HIJACKED" "$out"
out="$(as "$MEMBER" "$BROKER" run -- ./ta-probe </dev/null 2>&1)"; rc=$?
expect_rc "relative path refused" 126 "$rc" "$out"
ln -s "$PROBE" "$WORK/alias"
out="$(as "$MEMBER" "$BROKER" run -- "$WORK/alias" </dev/null 2>&1)"; rc=$?
expect_rc "symlink alias refused" 126 "$rc" "$out"
out="$(as "$MEMBER" "$BROKER" run -- ta-probe $'\xff' </dev/null 2>&1)"; rc=$?
expect_rc "non-UTF-8 argument refused" 126 "$rc" "$out"

section "denial and access control"
touch "$WORK/keep"
chmod 666 "$WORK/keep"
out="$(as "$MEMBER" "$BROKER" run -- ta-denied "$WORK/keep" </dev/null 2>&1)"; rc=$?
expect_rc "deny rule refuses" 126 "$rc" "$out"
expect_has "the deny rule is what refused it" "denied by rule" "$out"
if [[ -e "$WORK/keep" ]]; then pass "denied command left the file"; else fail "denied command left the file"; fi
out="$(as "$MEMBER" "$BROKER" run -- /usr/bin/rm "$WORK/keep" </dev/null 2>&1)"; rc=$?
if [[ "$(readlink -f /usr/bin/rm)" != /usr/bin/rm ]]; then
  expect_rc "symlinked system tool refused as an alias" 126 "$rc" "$out"
  expect_has "the alias check is what refused it" "alias" "$out"
else
  echo "  skip  rm is not a symlink on this system"
fi
out="$(as "$MEMBER" "$BROKER" run -- id </dev/null 2>&1)"; rc=$?
expect_rc "broker refuses user-verdict commands" 126 "$rc" "$out"
out="$(as "$OUTSIDER" "$BROKER" run -- ta-probe </dev/null 2>&1)"; rc=$?
expect_rc "non-member cannot execute the broker" 126 "$rc" "$out"
expect_not "non-member got nothing" "euid=" "$out"
out="$(as "$MEMBER" "$BROKER" run -- /usr/bin/bash -c id </dev/null 2>&1)"; rc=$?
expect_rc "unlisted shell refused without approval" 126 "$rc" "$out"

section "policy protection (fail closed)"
chmod 0666 "$POLICY"
out="$(as "$MEMBER" "$BROKER" run -- ta-probe </dev/null 2>&1)"; rc=$?
expect_rc "world-writable policy refused" 126 "$rc" "$out"
chmod 0644 "$POLICY"
chown "$MEMBER" "$POLICY"
out="$(as "$MEMBER" "$BROKER" run -- ta-probe </dev/null 2>&1)"; rc=$?
expect_rc "user-owned policy refused" 126 "$rc" "$out"
chown root "$POLICY"
cp "$POLICY" "$WORK/policy.bak"
echo 'garbage = [' >"$POLICY"
out="$(as "$MEMBER" "$BROKER" run -- ta-probe </dev/null 2>&1)"; rc=$?
expect_rc "malformed policy refused" 126 "$rc" "$out"
cp "$WORK/policy.bak" "$POLICY"
printf '[[rule]]\nid = "x"\naction = "allow"\nbin = "/usr/bin/bash"\nargs = []\n' >>"$POLICY"
out="$(as "$MEMBER" "$BROKER" run -- ta-probe </dev/null 2>&1)"; rc=$?
expect_rc "policy auto-elevating a shell refused" 126 "$rc" "$out"
cp "$WORK/policy.bak" "$POLICY"
rm "$POLICY"
out="$(as "$MEMBER" "$BROKER" run -- ta-probe </dev/null 2>&1)"; rc=$?
expect_rc "missing policy refused" 126 "$rc" "$out"
cp "$WORK/policy.bak" "$POLICY"; chmod 0644 "$POLICY"

section "audit log"
: >"$AUDIT"
as "$MEMBER" "$BROKER" run -- ta-probe >/dev/null </dev/null 2>&1
as "$MEMBER" "$BROKER" run -- ta-probe echo $'evil\n{"uid":0}' >/dev/null </dev/null 2>&1
as "$MEMBER" "$BROKER" run -- ta-denied /nonexistent >/dev/null </dev/null 2>&1
out="$(python3 - "$AUDIT" <<'EOF'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1])]
print("rows", len(rows))
for r in rows:
    print(r["user"], r["event"], r["verdict"], r.get("rule"), r["args"])
EOF
)"; rc=$?
expect_rc "every line is valid JSON" 0 "$rc" "$out"
expect_has "allow recorded with its rule" "$MEMBER decision allow probe" "$out"
expect_has "deny recorded" "decision deny no-denied" "$out"
# Allow, the injected command's decision and failed approval, then the deny.
expect_has "injected newline stayed inside one record" "rows 4" "$out"
expect_has "injected text is kept as data" "['echo', 'evil\\n{\"uid\":0}']" "$out"

mv /var/log/trustauto /var/log/trustauto.moved
out="$(as "$MEMBER" "$BROKER" run -- ta-probe </dev/null 2>&1)"; rc=$?
expect_rc "no audit log, no elevation" 126 "$rc" "$out"
expect_not "command did not run without audit" "euid=" "$out"
mv /var/log/trustauto.moved /var/log/trustauto

mv "$AUDIT" "$AUDIT.real"
ln -s /etc/shadow "$AUDIT"
out="$(as "$MEMBER" "$BROKER" run -- ta-probe </dev/null 2>&1)"; rc=$?
expect_rc "symlinked audit log refused" 126 "$rc" "$out"
rm -f "$AUDIT"; mv "$AUDIT.real" "$AUDIT"

if chattr +i "$AUDIT" 2>/dev/null; then
  out="$(as "$MEMBER" "$BROKER" run -- ta-probe </dev/null 2>&1)"; rc=$?
  expect_rc "unwritable audit log refused" 126 "$rc" "$out"
  chattr -i "$AUDIT"
else
  echo "  skip  immutable audit log (filesystem has no chattr +i)"
fi

as "$APPROVER" "$BROKER" run -- ta-probe >/dev/null </dev/null 2>&1
out="$(as "$MEMBER" /usr/local/bin/trustauto history 100 2>&1)"
expect_not "members see only their own history" "\"user\":\"$APPROVER\"" "$out"
expect_has "members see their own entries" "\"user\":\"$MEMBER\"" "$out"
out="$(as "$APPROVER" /usr/local/bin/trustauto history 100 2>&1)"
expect_has "approvers see everyone" "\"user\":\"$MEMBER\"" "$out"
out="$(as "$OUTSIDER" cat "$AUDIT" 2>&1)"; rc=$?
expect_rc "outsiders cannot read the log" 1 "$rc" "$out"

section "approval through PAM"
DRIVER=(python3 "$ROOT/scripts/pty_driver.py")
out="$(as "$MEMBER" "$BROKER" run -- ta-probe ask-me </dev/null 2>&1)"; rc=$?
expect_rc "ask without a terminal is refused" 126 "$rc" "$out"

out="$("${DRIVER[@]}" --expect "approver username:" --send "$APPROVER" \
  --expect "assword" --send env:PASSWORD \
  -- runuser -u "$MEMBER" -- "$BROKER" run -- ta-probe ask-me 2>&1)"; rc=$?
expect_rc "approved command runs" 0 "$rc" "$out"
expect_has "approved command is root" "euid=0" "$out"
expect_not "password never echoed" "$PASSWORD" "$out"
expect_has "approval recorded" "\"event\":\"approved\"" "$(cat "$AUDIT")"
expect_has "approver recorded" "\"approver\":\"$APPROVER\"" "$(cat "$AUDIT")"

out="$("${DRIVER[@]}" --expect "approver username:" --send "$APPROVER" \
  --expect "assword" --send wrong1 --expect "assword" --send wrong2 \
  -- runuser -u "$MEMBER" -- "$BROKER" run -- ta-probe ask-me 2>&1)"; rc=$?
expect_rc "wrong password refused" 126 "$rc" "$out"
expect_not "wrong password did not run" "euid=" "$out"

out="$("${DRIVER[@]}" --expect "approver username:" --send "$MEMBER" \
  -- runuser -u "$MEMBER" -- "$BROKER" run -- ta-probe ask-me 2>&1)"; rc=$?
expect_rc "a non-approver cannot approve, even with their password" 126 "$rc" "$out"

out="$("${DRIVER[@]}" --expect "assword" --send env:PASSWORD \
  -- runuser -u "$APPROVER" -- "$BROKER" run -- ta-probe ask-me 2>&1)"; rc=$?
expect_rc "an approver can approve their own request" 0 "$rc" "$out"

out="$(CTRL_D=$'\x04' "${DRIVER[@]}" --expect "assword" --send env:CTRL_D \
  -- runuser -u "$APPROVER" -- "$BROKER" run -- ta-probe ask-me 2>&1)"; rc=$?
expect_rc "Ctrl-D at the password prompt refuses" 126 "$rc" "$out"
expect_has "Ctrl-D cancels at once" "approval cancelled" "$out"
expect_not "Ctrl-D is not a failed password" "authentication failed" "$out"
expect_not "Ctrl-D did not run the command" "euid=" "$out"

# Never approved, so the only output that could carry the escape is the prompt.
out="$("${DRIVER[@]}" --expect "approver username:" --send "$OUTSIDER" \
  -- runuser -u "$MEMBER" -- "$BROKER" run -- ta-probe echo $'bad\e[2Kname' 2>&1)"; rc=$?
expect_rc "refused after a non-approver name" 126 "$rc" "$out"
expect_not "escape codes in arguments do not reach the prompt" $'\e[2K' "$out"
expect_has "the prompt shows the escape as text" 'bad\u{1b}[2Kname' "$out"

section "terminal requirement"
write_policy rule true
out="$(as "$MEMBER" "$BROKER" run -- ta-probe </dev/null 2>&1)"; rc=$?
expect_rc "no terminal, no automatic elevation" 126 "$rc" "$out"
out="$("${DRIVER[@]}" -- runuser -u "$MEMBER" -- "$BROKER" run -- ta-probe 2>&1)"; rc=$?
expect_rc "a terminal allows automatic elevation" 0 "$rc" "$out"
expect_has "elevated on a terminal" "euid=0" "$out"
write_policy rule false

section "machine facts"
FACTS=/var/lib/trustauto/facts.json
INDEX=/var/lib/trustauto/facts.index.json
expect_has "installer collected the facts" "640 root trustauto" "$(stat -c '%a %U %G' "$FACTS" 2>&1)"
expect_has "installer built the index" "640 root trustauto" "$(stat -c '%a %U %G' "$INDEX" 2>&1)"
# Searched in the whole file: dpkg's status text comes first and can be larger than any fixed prefix.
expect_has "facts list dpkg packages" '"lists"' "$(grep -o -m1 '"lists"' "$FACTS")"
out="$(as "$OUTSIDER" cat "$FACTS" 2>&1)"; rc=$?
expect_rc "a non-member cannot read the facts" 1 "$rc" "$out"
out="$(as "$OUTSIDER" cat "$INDEX" 2>&1)"; rc=$?
expect_rc "a non-member cannot read the index" 1 "$rc" "$out"
out="$(as "$MEMBER" /usr/lib/trustauto/trustauto-facts collect 2>&1)"; rc=$?
expect_rc "collecting needs root" 1 "$rc" "$out"
if [[ -d /run/systemd/system ]]; then
  expect_has "the daily refresh is enabled" "enabled" "$(systemctl is-enabled trustauto-facts.timer 2>&1)"
fi

section "ML modes"
out="$(as "$MEMBER" "$BROKER" run -- ta-probe ceiling </dev/null 2>&1)"; rc=$?
expect_rc "rule mode does not elevate an envelope" 126 "$rc" "$out"
# Decisions read only the index, so it is the one that goes missing.
mv "$INDEX" "$INDEX.saved"
for mode in ml hybrid; do
  write_policy "$mode" false
  out="$(as "$MEMBER" "$BROKER" run -- ta-probe ceiling </dev/null 2>&1)"; rc=$?
  expect_rc "$mode without facts fails closed" 126 "$rc" "$out"
  out="$(as "$MEMBER" "$BROKER" run -- ta-probe </dev/null 2>&1)"; rc=$?
  expect_rc "$mode without facts also holds allow rules" 126 "$rc" "$out"
done
mv "$INDEX.saved" "$INDEX"
for mode in ml hybrid; do
  write_policy "$mode" false
  out="$(as "$MEMBER" "$BROKER" run -- /usr/bin/bash -c id </dev/null 2>&1)"; rc=$?
  expect_rc "$mode never elevates a shell" 126 "$rc" "$out"
done
write_policy hybrid false
out="$(as "$MEMBER" /usr/local/bin/trustauto explain -- ta-probe ceiling 2>&1)"
expect_has "hybrid scores an envelope" "ml risk:" "$out"
# The front end leaves model decisions to the broker, which shows the one face.
# Allow or Ask both count; an approval prompt gets a non-approver and fails.
out="$("${DRIVER[@]}" --expect "approver username" --send nobody -- runuser -u "$MEMBER" -- /usr/local/bin/trustauto run -- ta-probe 2>&1)"
faces="$(grep -o -E '\^ \^|\? \?' <<<"$out" | wc -l)"
if [[ "$faces" -eq 1 ]]; then pass "a model decision shows one face"; else fail "a model decision shows one face" "$faces faces in: $out"; fi
write_policy ml false
out="$(as "$MEMBER" /usr/local/bin/trustauto explain -- systemctl restart cron 2>&1)"
expect_has "ml mode scores a command without a rule" "ml risk:" "$out"
write_policy ml false
out="$(as "$MEMBER" /usr/local/bin/trustauto run -- id -u </dev/null 2>&1)"
expect_rc "ml mode keeps user rules" "$(id -u "$MEMBER")" "$out" "$out"
out="$(as "$MEMBER" /usr/local/bin/trustauto explain -- cat /etc/hostname 2>&1)"
expect_has "ml mode runs readable files with normal rights" "verdict:  user" "$out"
out="$(as "$MEMBER" /usr/local/bin/trustauto explain -- apt-get update 2>&1)"
expect_has "network commands never elevate in ml mode" "verdict:  ask" "$out"
write_policy rule false

section "mode command"
out="$(as "$MEMBER" /usr/local/bin/trustauto mode ml </dev/null 2>&1)"; rc=$?
expect_rc "only root changes the mode" 2 "$rc" "$out"
out="$(/usr/local/bin/trustauto mode ml </dev/null 2>&1)"; rc=$?
expect_rc "root selects ml mode" 0 "$rc" "$out"
expect_has "ml mode shows the high-risk question's default" "not trained on: no" "$out"
expect_has "the warning is shown" "ML のみモード" "$out"
expect_has "policy now says ml" 'mode = "ml"' "$(cat "$POLICY")"
expect_has "unknown programs keep asking by default" "judge_unknown = false" "$(cat "$POLICY")"
out="$(/usr/local/bin/trustauto mode ml --judge-unknown </dev/null 2>&1)"; rc=$?
expect_rc "root opts into judging unknown programs" 0 "$rc" "$out"
expect_has "policy records the opt-in" "judge_unknown = true" "$(cat "$POLICY")"
out="$(/usr/local/bin/trustauto mode rule </dev/null 2>&1)"; rc=$?
expect_rc "root returns to rule mode" 0 "$rc" "$out"
expect_has "policy is still trusted after the change" "ok (" "$(as "$MEMBER" /usr/local/bin/trustauto check 2>&1)"
expect_has "policy stays 0644 root" "644 root root" "$(stat -c '%a %U %G' "$POLICY")"
write_policy rule false

section "front end and shell integration"
out="$(as "$MEMBER" /usr/local/bin/trustauto run -- ta-probe </dev/null 2>&1)"; rc=$?
expect_rc "cli reaches the broker" 0 "$rc" "$out"
expect_has "cli elevation works" "euid=0" "$out"
out="$(as "$MEMBER" /usr/local/bin/trustauto run -- id -u </dev/null 2>&1)"; rc=$?
expect_rc "user verdict runs" 0 "$rc" "$out"
if [[ "$out" == "$(id -u "$MEMBER")" ]]; then
  pass "user verdict is not elevated"
else
  fail "user verdict is not elevated" "$out"
fi
out="$(as "$MEMBER" /usr/local/bin/trustauto run -- ta-probe </dev/null 2>&1)"
expect_not "no face on a pipe" "^ ^" "$out"
out="$("${DRIVER[@]}" -- runuser -u "$MEMBER" -- /usr/local/bin/trustauto run -- ta-probe 2>&1)"; rc=$?
expect_rc "cli runs on a terminal" 0 "$rc" "$out"
expect_has "elevation shows its face" "^ ^" "$out"
expect_has "elevation still happens with a face" "euid=0" "$out"
out="$("${DRIVER[@]}" -- runuser -u "$MEMBER" -- env TRUSTAUTO_FACE=off /usr/local/bin/trustauto run -- ta-probe 2>&1)"
expect_not "the face can be turned off" "^ ^" "$out"
out="$("${DRIVER[@]}" -- runuser -u "$MEMBER" -- env NO_COLOR=1 /usr/local/bin/trustauto run -- ta-probe 2>&1)"
expect_has "no colour draws a plain face" "[^ ^]" "$out"
out="$("${DRIVER[@]}" -- runuser -u "$MEMBER" -- /usr/local/bin/trustauto run -- id -u 2>&1)"
expect_not "a user verdict stays silent on a terminal" "0 0" "$out"
out="$(as "$MEMBER" /usr/local/bin/trustauto explain -- ta-denied /x 2>&1)"
expect_has "explain shows the verdict" "verdict:  deny" "$out"
install -m 0644 "$ROOT/config/policy.toml" "$WORK/sample-policy.toml"
for command in "apt update" "apt install htop" "apt search vim" "systemctl daemon-reload" \
  "systemctl restart nginx.service" "journalctl -u ssh --no-pager" "dmesg" "ufw status"; do
  # shellcheck disable=SC2086
  out="$(as "$MEMBER" /usr/local/bin/trustauto explain --policy "$WORK/sample-policy.toml" -- $command 2>&1)"; rc=$?
  expect_rc "sample policy resolves on this system: $command" 0 "$rc" "$out"
  expect_not "sample policy rule matches: $command" "no rule matches" "$out"
done
out="$(as "$OUTSIDER" /usr/local/bin/trustauto run -- ta-probe </dev/null 2>&1)"; rc=$?
expect_rc "cli gives a non-member nothing" 126 "$rc" "$out"

rc_line='eval "$(trustauto shell-init bash)"'
out="$(as "$MEMBER" env PATH=/usr/local/bin:/usr/bin:/bin bash --norc --noprofile -ic "$rc_line; ta-probe" </dev/null 2>&1)"
expect_has "bash wrapper elevates without sudo" "euid=0" "$out"
out="$(as "$MEMBER" env PATH=/usr/local/bin:/usr/bin:/bin bash --norc --noprofile -ic "$rc_line; ta-probe echo 'one' | sed -n 's/^args=/piped:/p'" </dev/null 2>&1)"
expect_has "bash wrapper works in a pipeline" "piped:echo one" "$out"
out="$(as "$MEMBER" env PATH=/usr/local/bin:/usr/bin:/bin bash --norc --noprofile -ic "$rc_line; ta-sprobe" </dev/null 2>&1)"
expect_has "bash reaches sbin through the wrapper" "euid=0" "$out"
out="$(as "$MEMBER" env PATH=/usr/local/bin:/usr/bin:/bin bash --norc --noprofile -ic "$rc_line; definitely-not-a-command" </dev/null 2>&1)"
expect_has "bash keeps normal command-not-found" "command not found" "$out"
out="$(as "$MEMBER" env PATH=/usr/local/bin:/usr/bin:/bin bash --norc --noprofile -c "$rc_line; type ta-probe || true" </dev/null 2>&1)"
expect_not "non-interactive shells are untouched" "function" "$out"

if command -v zsh >/dev/null; then
  zsh_line='eval "$(trustauto shell-init zsh)"'
  out="$(as "$MEMBER" env PATH=/usr/local/bin:/usr/bin:/bin zsh -f -ic "$zsh_line; ta-probe" </dev/null 2>&1)"
  expect_has "zsh wrapper elevates without sudo" "euid=0" "$out"
  out="$(as "$MEMBER" env PATH=/usr/local/bin:/usr/bin:/bin zsh -f -ic "$zsh_line; ta-sprobe" </dev/null 2>&1)"
  expect_has "zsh reaches sbin through the hook" "euid=0" "$out"
  out="$(as "$MEMBER" env PATH=/usr/local/bin:/usr/bin:/bin zsh -f -ic "$zsh_line; definitely-not-a-command" </dev/null 2>&1)"
  expect_has "zsh keeps normal command-not-found" "command not found" "$out"
else
  echo "  skip  zsh is not installed (apt install zsh to cover it)"
fi

section "on, off, log, setting and help"
CLI=/usr/local/bin/trustauto
out="$(as "$MEMBER" "$CLI" setting 2>&1)"; rc=$?
expect_rc "setting works" 0 "$rc" "$out"
expect_has "setting starts on" "state:   on" "$out"
expect_has "setting shows the rule mode" "mode:    rule (rules only)" "$out"
expect_has "setting shows the model" "model:   facts transformer" "$out"
expect_has "setting shows the facts" "facts:   /var/lib/trustauto/facts.index.json" "$out"
out="$(as "$MEMBER" "$CLI" off 2>&1)"; rc=$?
expect_rc "off works" 0 "$rc" "$out"
expect_has "setting shows off" "state:   off" "$(as "$MEMBER" "$CLI" setting 2>&1)"
out="$(as "$MEMBER" env PATH=/usr/local/bin:/usr/bin:/bin "$CLI" run -- ta-probe </dev/null 2>&1)"; rc=$?
expect_rc "off still runs the command" 0 "$rc" "$out"
expect_has "off runs it with normal rights" "euid=$(id -u "$MEMBER") " "$out"
expect_not "off does not elevate" "euid=0" "$out"
out="$(as "$MEMBER" env HOME=/nonexistent PATH=/usr/local/bin:/usr/bin:/bin "$CLI" run -- ta-probe </dev/null 2>&1)"
expect_not "off does not depend on HOME" "euid=0" "$out"
out="$(as "$MEMBER" env PATH=/usr/local/bin:/usr/bin:/bin bash --norc --noprofile -ic "$rc_line; ta-probe" </dev/null 2>&1)"
expect_has "an open shell's wrapper obeys off" "euid=$(id -u "$MEMBER") " "$out"
out="$(as "$MEMBER" env PATH=/usr/local/bin:/usr/bin:/bin bash --norc --noprofile -ic "$rc_line; ta-sprobe" </dev/null 2>&1)"; rc=$?
expect_not "off gives sbin programs no elevation" "euid=0" "$out"
expect_rc "a program outside PATH is not found while off" 127 "$rc" "$out"
as "$MEMBER" "$CLI" known ta-sprobe; rc=$?
expect_rc "the command-not-found hook skips everything while off" 1 "$rc" ""
expect_has "explain says it is off" "trustauto is off" "$(as "$MEMBER" "$CLI" explain -- ta-probe 2>&1)"
out="$(as "$OUTSIDER" "$CLI" setting 2>&1)"
expect_has "off applies to one user only" "state:   on" "$out"
out="$(as "$MEMBER" "$CLI" on 2>&1)"; rc=$?
expect_rc "on works" 0 "$rc" "$out"
out="$(as "$MEMBER" "$CLI" run -- ta-probe </dev/null 2>&1)"; rc=$?
expect_has "on elevates again" "euid=0" "$out"
out="$("$CLI" off 2>&1)"; rc=$?
expect_rc "root has nothing to switch" 2 "$rc" "$out"
out="$(as "$MEMBER" "$CLI" log 2>/dev/null)"; rc=$?
expect_rc "log works" 0 "$rc" "$out"
if [[ "$out" == "$AUDIT" ]]; then pass "log prints only the path"; else fail "log prints only the path" "$out"; fi
expect_has "log points members to history" "trustauto history" "$(as "$MEMBER" "$CLI" log 2>&1 >/dev/null)"
out="$(as "$MEMBER" "$CLI" help 2>&1)"
for word in "trustauto on" "trustauto off" "trustauto setting" "trustauto mode" "trustauto log" "trustauto help"; do
  expect_has "help lists $word" "$word" "$out"
done

section "spec targets"
# Process names are cut at 15 characters, and pgrep refuses longer patterns.
if pgrep -x trustauto >/dev/null || pgrep -x trustauto-broke >/dev/null; then
  fail "no process stays resident" "$(pgrep -ax trustauto; pgrep -ax trustauto-broke)"
else
  pass "no process stays resident (idle RAM 0 MB)"
fi
ls -l "$ROOT/ml/facts_model.bin" 2>/dev/null | awk '{print "  model file: " $5 " bytes"}'
if [[ -x "$BIN_DIR/trustauto-bench" ]]; then
  "$BIN_DIR/trustauto-bench" /var/lib/trustauto/facts.json
fi

echo
echo "passed $PASS, failed $FAIL"
[[ "$FAIL" -eq 0 ]]
