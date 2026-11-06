#!/usr/bin/env python3
"""Runs commands outside the package and service cases, and records what really changed.

truth_lab.py only sees whether a capability still works, so `chmod u+s /bin/bash`
looks harmless there. This lab keeps those checks and adds what a command gave away:
each case compares the container's overlay upper layer before and after the command.
The layer holds every file the container changed, so nothing depends on the command's
own report. Canary secrets show whether a command disclosed or copied a protected file.

Run as root in a disposable VM only:

  TRUSTAUTO_TRUTH_DISPOSABLE=yes TRUSTAUTO_TRUTH_PROFILE=NAME action_lab.py case CASES_JSONL ID
  TRUSTAUTO_TRUTH_DISPOSABLE=yes TRUSTAUTO_TRUTH_PROFILE=NAME action_lab.py batch CASES_JSONL OUT_JSONL [WORKERS]

Rows hold raw observations and no label. The training step decides which count as
risky, and `control` cases show what changes when a command does nothing.

Containers cannot observe the kernel, block devices or bootloader, so commands aimed
at those are not cases here. A result of "no change" means no change that this lab can see.

Cases come from public corpora and include attack recipes, so nothing may leave:
- commands run through systemd-run inside the container, under its capability limits and
  seccomp filter (nsenter would keep the host's), with no network but loopback
- `batch` refuses to start if a container has a route out, and only fixed apt commands
  ever run offline, on the host network. Corpus runs also need lab_firewall.sh on the VM.
"""
import concurrent.futures
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import threading
import time

import truth_lab as lab

OUTPUT_KEPT = 1 << 20
# Not secrets. Fake values planted in each throwaway container (as a password hash, an
# SSH private key and a TLS key) so a command that leaks them shows up in its output.
# The "-----BEGIN OPENSSH PRIVATE KEY-----" written below wraps a canary, not a key;
# a secret scanner that flags it can be told so.
CANARIES = {
    "shadow": "TACANARYshadow7f3a91",
    "root_key": "TACANARYrootkey52c8e0",
    "tls_key": "TACANARYtlskey0d94b6",
}
# Changes under these come from services running, not from the command under test.
# apt keeps its own files under var/lib/apt/lists, and nspawn writes resolv.conf when it lends the host network.
NOISE = re.compile(r"^(var/tmp/ta-exec\.log$|var/log/|var/cache(/|$)|var/tmp/systemd-|tmp/systemd-|run/|var/lib/systemd/(random-seed|timers|catalog|coredump)|var/lib/apt/lists/|var/lib/dpkg/lock|etc/resolv\.conf$|etc/machine-id$)")
# Who is allowed to run things as root comes from these.
SECURITY_PATHS = {
    "sudoers": re.compile(r"^etc/(sudoers$|sudoers\.d/)"),
    "ssh_keys": re.compile(r"^(root|home/[^/]+)/\.ssh/"),
    "ssh_config": re.compile(r"^etc/ssh/(sshd_config|ssh_host_)"),
    "pam": re.compile(r"^(etc/pam\.d/|etc/security/|etc/nsswitch\.conf$)"),
    "preload": re.compile(r"^etc/ld\.so\.(preload|conf)"),
    "persistence": re.compile(r"^(etc/cron|var/spool/cron/|etc/systemd/system/|etc/rc\.local$|etc/init\.d/|etc/profile|etc/environment$|etc/bash\.bashrc$|root/\.(bash|profile)|etc/modules|etc/modprobe\.d/|etc/udev/rules\.d/)"),
    "package_trust": re.compile(r"^etc/apt/(sources|trusted|apt\.conf|preferences)"),
}
SYSTEM_DIRS = re.compile(r"^(etc|usr|bin|sbin|lib|lib64|boot|root|opt|srv|var/lib|var/spool)(/|$)")
PRIVILEGED_GROUPS = {"root", "sudo", "wheel", "adm", "shadow", "disk", "docker", "lxd", "systemd-journal"}
WRITE_TO_ANYONE = stat.S_IWOTH
EXEC_LOG = "/var/tmp/ta-exec.log"
INTERPRETER = re.compile(r"^(sh|ash|dash|bash|rbash|zsh|ksh|csh|tcsh|fish|busybox|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|php[0-9.]*|node|lua[0-9.]*|tclsh[0-9.]*|expect|gdb)$")
STICKY_DIRS = {"tmp", "var/tmp", "var/lock", "dev/shm"}
# Memory filesystems in a booted container, so what lands here never reaches the overlay layer.
VOLATILE = ("tmp", "dev/shm")
# Network settings that change by themselves or differ at every read.
MOVING_SYSCTL = re.compile(r"(_count|_key|stable_secret|\.flush|hash_secret|random)")


def walk_layer(root):
    """Returns path -> (mode, uid, gid, size, mtime_ns) for everything in a layer."""
    entries = {}
    root = str(root)
    for parent, dirs, files in os.walk(root):
        for name in dirs + files:
            path = os.path.join(parent, name)
            try:
                st = os.lstat(path)
            except OSError:
                continue
            # Overlayfs records a deletion as a 0:0 character device.
            deleted = stat.S_ISCHR(st.st_mode) and st.st_rdev == 0
            # A directory's time and size change with its children, which are listed themselves.
            is_dir = stat.S_ISDIR(st.st_mode)
            entries[os.path.relpath(path, root)] = {
                "mode": st.st_mode, "uid": st.st_uid, "gid": st.st_gid,
                "size": 0 if is_dir else st.st_size, "mtime": 0 if is_dir else st.st_mtime_ns,
                "dir": is_dir, "deleted": deleted,
            }
    return entries


def walk_volatile(leader):
    """The same as walk_layer, for the container's memory filesystems, seen from outside it."""
    if not leader:
        return {}
    base = pathlib.Path(f"/proc/{leader}/root")
    return {f"{area}/{rel}": entry for area in VOLATILE for rel, entry in walk_layer(base / area).items()}


def changed_paths(before, after):
    """Paths the command touched, leaving out what running services keep touching."""
    changed = {p for p, e in after.items() if before.get(p) != e and not NOISE.match(p)}
    # Writing a file copies its parent directories into the layer, unchanged.
    parents = {str(parent) for p in changed for parent in pathlib.PurePath(p).parents}
    return sorted(p for p in changed if not (p in parents and p not in before and after[p]["dir"]))


def read_accounts(root):
    """Who can act as root, read from the account files of a directory tree."""
    root = pathlib.Path(root)
    uid0, empty, members = set(), set(), {}
    try:
        for line in (root / "etc/passwd").read_text(errors="replace").splitlines():
            fields = line.split(":")
            if len(fields) > 2 and fields[2] == "0":
                uid0.add(fields[0])
    except OSError:
        pass
    try:
        for line in (root / "etc/shadow").read_text(errors="replace").splitlines():
            fields = line.split(":")
            if len(fields) > 1 and fields[1] == "":
                empty.add(fields[0])
    except OSError:
        pass
    try:
        for line in (root / "etc/group").read_text(errors="replace").splitlines():
            fields = line.split(":")
            if len(fields) > 3 and fields[0] in PRIVILEGED_GROUPS:
                members[fields[0]] = {m for m in fields[3].split(",") if m}
    except OSError:
        pass
    return {"uid0": uid0, "empty_password": empty, "groups": members}


def account_changes(before, after):
    out = {}
    if after["uid0"] - before["uid0"]:
        out["new_uid0"] = sorted(after["uid0"] - before["uid0"])
    if after["uid0"] < before["uid0"]:
        out["lost_uid0"] = sorted(before["uid0"] - after["uid0"])
    if after["empty_password"] - before["empty_password"]:
        out["new_empty_password"] = sorted(after["empty_password"] - before["empty_password"])
    joined = {}
    for group, users in after["groups"].items():
        added = users - before["groups"].get(group, set())
        if added:
            joined[group] = sorted(added)
    if joined:
        out["joined_privileged_group"] = joined
    return out


def has_capability(path):
    try:
        return bool(os.getxattr(path, "security.capability", follow_symlinks=False))
    except (OSError, AttributeError):
        return False


def inspect_changes(paths, merged, lowers, upper):
    """Sorts changed paths by what they give away. `lowers` hold each file's earlier state."""
    merged, upper = pathlib.Path(merged), pathlib.Path(upper)
    found = {"new_setuid": [], "new_capability": [], "opened_to_all": [], "owner_not_root": [], "deleted": []}
    for name in SECURITY_PATHS:
        found[name] = []
    found["files_changed"] = len(paths)
    for rel in paths:
        for name, pattern in SECURITY_PATHS.items():
            if pattern.match(rel):
                found[name].append(rel)
        try:
            st = os.lstat(upper / rel)
        except OSError:
            continue
        if stat.S_ISCHR(st.st_mode) and st.st_rdev == 0:
            found["deleted"].append(rel)
            continue
        if stat.S_ISLNK(st.st_mode):
            continue
        earlier = None
        for lower in lowers:
            try:
                earlier = os.lstat(pathlib.Path(lower) / rel)
                break
            except OSError:
                pass
        bits = stat.S_ISUID | stat.S_ISGID
        if st.st_mode & bits and stat.S_ISREG(st.st_mode) and not (earlier and earlier.st_mode & bits):
            found["new_setuid"].append(rel)
        if stat.S_ISREG(st.st_mode) and has_capability(upper / rel):
            found["new_capability"].append(rel)
        if SYSTEM_DIRS.match(rel) and rel not in STICKY_DIRS:
            if st.st_mode & WRITE_TO_ANYONE and not (earlier and earlier.st_mode & WRITE_TO_ANYONE):
                found["opened_to_all"].append(rel)
            # Services keep their own new files under var/lib and var/spool, which gives nothing away.
            if st.st_uid != 0 and (earlier.st_uid == 0 if earlier else not rel.startswith(("var/lib/", "var/spool/"))):
                found["owner_not_root"].append(rel)
    return {k: v[:40] if isinstance(v, list) else v for k, v in found.items() if v}


def merge_changes(first, second):
    out = dict(first)
    for key, value in second.items():
        out[key] = out.get(key, 0) + value if key == "files_changed" else (out.get(key, []) + value)[:40]
    return out


def secrets_copied(paths, upper):
    """Canaries that ended up in a file another user can read."""
    upper, seen = pathlib.Path(upper), set()
    for rel in paths:
        target = upper / rel
        try:
            st = os.lstat(target)
            if not stat.S_ISREG(st.st_mode) or st.st_size > 2_000_000 or not st.st_mode & stat.S_IROTH:
                continue
            text = target.read_text(errors="replace")
        except OSError:
            continue
        seen |= {name for name, token in CANARIES.items() if token in text}
    return sorted(seen)


def secrets_in_output(text):
    return sorted(name for name, token in CANARIES.items() if token in text)


def plant_canaries(merged):
    """Puts protected secrets on the machine, the way a real one would have them."""
    merged = pathlib.Path(merged)
    shadow = merged / "etc/shadow"
    shadow.write_text(re.sub(rf"^{lab.USER}:[^:]*:", f"{lab.USER}:$6${CANARIES['shadow']}$x:",
                             shadow.read_text(), flags=re.M))
    ssh = merged / "root/.ssh"
    ssh.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = ssh / "id_ed25519"
    key.write_text(f"-----BEGIN OPENSSH PRIVATE KEY-----\n{CANARIES['root_key']}\n-----END OPENSSH PRIVATE KEY-----\n")
    key.chmod(0o600)
    tls = merged / "etc/ssl/private"
    tls.mkdir(parents=True, exist_ok=True)
    tls_key = tls / "ta-canary.key"
    tls_key.write_text(f"-----BEGIN PRIVATE KEY-----\n{CANARIES['tls_key']}\n-----END PRIVATE KEY-----\n")
    tls_key.chmod(0o600)


def without_loader_errors(text):
    """A broken ld.so.preload makes every program print this. It is not the program's output."""
    return "\n".join(line for line in text.splitlines() if not line.startswith("ERROR: ld.so:"))


def live_state(c):
    """What only a running machine can show. Runs inside the container's namespaces."""
    state = {"ports": [], "firewall": "", "sshd": {}, "units": [], "network": "", "hostname": "", "sysctl": {}}
    rc, out = c.inside("ss", "-ltnuH")
    if rc == 0:
        state["ports"] = sorted({f"{line.split()[0]} {line.split()[4].rsplit(':', 1)[-1]}"
                                 for line in without_loader_errors(out).splitlines() if len(line.split()) > 4})
    rc, out = c.inside("nft", "list", "ruleset")
    if rc == 0:
        state["firewall"] = without_loader_errors(out)
    rc, out = c.inside("sshd", "-T")
    if rc == 0:
        wanted = ("permitrootlogin", "passwordauthentication", "permitemptypasswords", "authorizedkeysfile")
        state["sshd"] = {line.split(None, 1)[0]: line.split(None, 1)[1] for line in out.splitlines()
                         if len(line.split(None, 1)) == 2 and line.split(None, 1)[0] in wanted}
    rc, out = c.inside("systemctl", "list-units", "--type=service,socket,timer", "--state=active", "--no-legend", "--plain")
    if rc == 0:
        state["units"] = sorted(line.split()[0] for line in without_loader_errors(out).splitlines() if line.split())
    for command in (("ip", "-o", "addr"), ("ip", "-o", "route"), ("ip", "-o", "link")):
        rc, out = c.inside(*command)
        if rc == 0:
            state["network"] += without_loader_errors(out) + "\n"
    rc, out = c.inside("hostname")
    if rc == 0:
        state["hostname"] = without_loader_errors(out).strip()
    rc, out = c.inside("sysctl", "net.ipv4", "net.ipv6", "net.core")
    if rc == 0:
        state["sysctl"] = {k.strip(): v.strip() for k, v in (line.split("=", 1) for line in out.splitlines() if " = " in line)
                           if not MOVING_SYSCTL.search(k)}
    return state


def live_changes(before, after):
    out = {}
    new_ports = sorted(set(after["ports"]) - set(before["ports"]))
    if new_ports:
        out["new_ports"] = new_ports
    if before["firewall"] != after["firewall"]:
        out["firewall_changed"] = True
    sshd = {k: [before["sshd"].get(k), v] for k, v in after["sshd"].items() if before["sshd"].get(k) != v}
    if sshd:
        out["sshd_changed"] = sshd
    # What only lasts while the machine runs: no file shows these, and none of it counts as no change.
    started = sorted(set(after.get("units", ())) - set(before.get("units", ())))
    stopped = sorted(set(before.get("units", ())) - set(after.get("units", ())))
    if started:
        out["units_started"] = started
    if stopped:
        out["units_stopped"] = stopped
    if before.get("network") != after.get("network"):
        out["network_changed"] = True
    if before.get("hostname") != after.get("hostname"):
        out["hostname_changed"] = True
    sysctl = sorted(k for k, v in after.get("sysctl", {}).items() if before.get("sysctl", {}).get(k) != v)
    if sysctl:
        out["sysctl_changed"] = sysctl[:20]
    return out


def run_confined(c, argv, text, timeout):
    """Runs a case inside the container's own limits, and logs every program it starts."""
    wrapper = ["systemd-run", "-M", c.name, "--pipe", "--wait", "--quiet", "--collect",
               "-p", "TasksMax=512", "-p", "MemoryMax=1G", "-p", f"RuntimeMaxSec={timeout}",
               "--working-directory=/root", "--", "strace", "-f", "-qq", "-e", "trace=execve",
               "-o", EXEC_LOG, "--", *argv]
    try:
        p = subprocess.Popen(wrapper, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=lab.ENV)
    except OSError as e:
        return 127, str(e)
    kept = []
    reader = threading.Thread(target=lambda: kept.append(read_output(p.stdout)), daemon=True)
    reader.start()
    threading.Thread(target=feed, args=(p.stdin, text), daemon=True).start()
    try:
        rc = p.wait(timeout + 15)
    except subprocess.TimeoutExpired:
        p.kill()
        rc = 124
    # Something the case left running can hold the pipe open after the wrapper has gone.
    reader.join(5)
    return rc, kept[0] if kept else "timeout"


def feed(stream, text):
    try:
        stream.write(text.encode())
        stream.close()
    except OSError:
        pass


def read_output(stream, keep=OUTPUT_KEPT):
    """The end of a case's output, and every canary in all of it. `yes` alone once filled the VM's memory."""
    longest = max(len(token) for token in CANARIES.values())
    tail, seen = b"", set()
    while chunk := stream.read1(65536):
        joined = tail[-longest:] + chunk
        seen |= {token for token in CANARIES.values() if token.encode() in joined}
        tail = (tail + chunk)[-keep:]
    return "".join(f"{token}\n" for token in sorted(seen)) + tail.decode(errors="replace")


def programs_started(log_text):
    """Programs a case started, in order, leaving out the command itself."""
    found = re.findall(r'execve\("([^"]+)", \[.*\) = 0', log_text)
    return found[1:]


def started_code(programs):
    """Shells and interpreters a command launched: a sign that it can run anything."""
    return sorted({p for p in programs if INTERPRETER.match(pathlib.PurePath(p).name)})


def check_isolation():
    """Stops before any case if a container could reach anything but itself."""
    with lab.Container() as c:
        if c.boot() is None:
            raise RuntimeError("the untouched machine does not boot")
        rc, routes = c.inside("ip", "-o", "route", "show", "table", "all")
        outside = [line for line in routes.splitlines()
                   if not re.search(r"\bdev lo\b", line) and not line.startswith(("local", "broadcast"))]
        rc_links, links = c.inside("ip", "-o", "link")
        names = {line.split(":")[1].strip().split("@")[0] for line in links.splitlines() if ":" in line}
        if rc or rc_links or outside or names - {"lo"}:
            raise RuntimeError(f"container network is not private: {names} {outside}")
        rc, out = run_confined(c, ["true"], "", 30)
        if rc != 0:
            raise RuntimeError(f"cannot run commands confined: {rc}: {out[-300:]}")
        return live_state(c)


def wait_until_gone(c, seconds=60):
    """A machine's name stays taken until its services stop (31 s on ubu24), and booting then would look like a broken machine."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if lab.run(["machinectl", "show", c.name], 5)[0] != 0:
            return
        time.sleep(0.5)
    raise RuntimeError("container did not go away")


UNTOUCHED = {}


def run_case(case):
    """`how` is `live` for a running machine, or `offline` for apt, which needs the network."""
    started = time.monotonic()
    try:
        with lab.Container() as c:
            upper = c.dir / "tmp" / "upper"
            lowers = [lab.GOLDEN, lab.LOWER]
            plant_canaries(c.merged)
            accounts_before = read_accounts(c.merged)
            live_before = None
            if case["how"] == "live":
                booted = c.boot()
                time.sleep(lab.SETTLE_SECONDS)
                live_before = live_state(c)
            layer_before = walk_layer(upper)
            volatile_before = walk_volatile(c.leader)
            start = time.monotonic()
            if case["how"] == "live":
                rc, out = run_confined(c, case["argv"], case.get("stdin", ""), case.get("timeout", lab.ACTION_TIMEOUT))
            elif case["kind"].startswith("apt_"):
                rc, out = c.offline(case["argv"])
            else:
                raise ValueError("only fixed apt commands may run with the host network")
            action = {"rc": rc, "seconds": round(time.monotonic() - start, 1), "tail": out[-500:] if rc else "",
                      "secrets_in_output": secrets_in_output(out)}
            time.sleep(lab.SETTLE_SECONDS)
            log = c.merged / EXEC_LOG.lstrip("/")
            programs = programs_started(log.read_text(errors="replace")) if log.exists() else None
            action["programs"] = None if programs is None else programs[:40]
            action["started_code"] = None if programs is None else started_code(programs)

            # Before the checks, which log in and run apt, and the reboot, which regenerates files.
            paths = changed_paths(layer_before, walk_layer(upper))
            volatile = changed_paths(volatile_before, walk_volatile(c.leader)) if c.leader and c.proc.poll() is None else []
            volatile_root = f"/proc/{c.leader}/root"
            result = {
                "changes": merge_changes(inspect_changes(paths, c.merged, lowers, upper),
                                         inspect_changes(volatile, volatile_root, [], volatile_root)),
                "accounts": account_changes(accounts_before, read_accounts(c.merged)),
                "secrets_copied": sorted(set(secrets_copied(paths, upper)) | set(secrets_copied(volatile, volatile_root))),
                "changed_paths": (paths + volatile)[:200],
            }
            if case["how"] == "live":
                checks_now = lab.checks(c, booted)
                live_after = live_state(c) if c.proc.poll() is None else None
            else:
                checks_now, live_after = None, None
            # A command that changed nothing cannot break the next boot, so skip the cost.
            if case["how"] == "live" and not paths and c.proc.poll() is None:
                booted_again, checks_after = booted, None
            else:
                c.stop()
                wait_until_gone(c)
                booted_again = c.boot()
                time.sleep(lab.SETTLE_SECONDS)
                checks_after = lab.checks(c, booted_again)
            if live_before and live_after:
                result["live"] = live_changes(live_before, live_after)
            if not live_before and booted_again is not None:
                # An offline command has no running machine before it, so compare with an untouched boot.
                result["live"] = live_changes({"ports": UNTOUCHED.get("ports", []), "firewall": "", "sshd": {}},
                                              {"ports": live_state(c)["ports"], "firewall": "", "sshd": {}})
        return {"id": case["id"], "kind": case["kind"], "argv": case["argv"], "stdin": case.get("stdin", ""),
                "sources": case.get("sources", []), "target": case.get("target"),
                "target_mode": case.get("target_mode"), "how": case["how"], "action": action,
                "checks_now": checks_now, "checks_after_boot": checks_after,
                "boot_seconds": booted_again and round(booted_again, 1), "result": result,
                "total_seconds": round(time.monotonic() - started, 1)}
    except Exception as e:
        return {"id": case["id"], "kind": case["kind"], "argv": case["argv"], "error": str(e)[-500:]}


def main():
    if os.geteuid() != 0 or os.environ.get("TRUSTAUTO_TRUTH_DISPOSABLE") != "yes":
        sys.exit("run as root with TRUSTAUTO_TRUTH_DISPOSABLE=yes, in a disposable VM only")
    if not lab.PROFILE:
        sys.exit("set TRUSTAUTO_TRUTH_PROFILE: this lab only runs against built machines")
    lab.prepare()
    pathlib.Path("/run/ta-truth").mkdir(exist_ok=True)
    args = sys.argv[1:]
    how = None
    if "--how" in args:
        i = args.index("--how")
        how = args[i + 1]
        del args[i:i + 2]
    cases = [json.loads(line) for line in pathlib.Path(args[1]).read_text().splitlines() if line.strip()]
    cases = [c for c in cases if how is None or c["how"] == how]
    UNTOUCHED.update(check_isolation())
    if args[0] == "case":
        print(json.dumps(run_case(next(c for c in cases if c["id"] == args[2])), indent=1))
    elif args[0] == "batch":
        workers = int(args[3]) if len(args) > 3 else 3
        out = pathlib.Path(args[2])
        done = {json.loads(line)["id"] for line in out.read_text().splitlines()} if out.exists() else set()
        todo = [c for c in cases if c["id"] not in done]
        print(f"{len(todo)} to run, {len(done)} already done", flush=True)
        with open(out, "a") as sink, concurrent.futures.ThreadPoolExecutor(workers) as pool:
            for i, result in enumerate(pool.map(run_case, todo), 1):
                sink.write(json.dumps(result) + "\n")
                sink.flush()
                if i % 25 == 0:
                    print(f"{i}/{len(todo)}", flush=True)


if __name__ == "__main__":
    main()
