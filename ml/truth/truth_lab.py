#!/usr/bin/env python3
"""Finds out what a command really breaks, instead of asking metadata or a person.

Each case runs in a throwaway container: the VM's root is a read-only lower layer,
all writes land in a tmpfs that is discarded, and the network is private. After
the command, the container boots (or keeps running) and a fixed set of checks
looks for damage. A check only counts if it passed on the untouched baseline.

Run as root in a disposable VM only:

  TRUSTAUTO_TRUTH_DISPOSABLE=yes truth_lab.py baseline
  TRUSTAUTO_TRUTH_DISPOSABLE=yes truth_lab.py case remove htop
  TRUSTAUTO_TRUTH_DISPOSABLE=yes truth_lab.py batch CASES_FILE OUT_JSONL [--workers N]
  TRUSTAUTO_TRUTH_DISPOSABLE=yes truth_lab.py collect FACTS_JSON CASES_FILE

Containers cannot observe the kernel, initramfs or bootloader. `boot_files` only
checks that those files survive, so results for such packages are weaker.

TRUSTAUTO_TRUTH_PROFILE=NAME runs against a machine built by build_profile.sh instead
of the VM itself. Its roles get protocol probes, sent from outside the container so
that removing a client tool inside cannot fake a failure.
"""
import concurrent.futures
import json
import os
import pathlib
import shlex
import socket
import subprocess
import sys
import time
import uuid

ROOT = pathlib.Path("/var/lib/ta-truth")
PROFILE = os.environ.get("TRUSTAUTO_TRUTH_PROFILE", "")
PROFILE_DIR = ROOT / "profiles" / PROFILE if PROFILE else None
# Outside the root filesystem: overlayfs refuses layers nested inside each other.
GOLDEN = pathlib.Path("/run/ta-truth-golden" + (f"-{PROFILE}" if PROFILE else ""))
KEY = ROOT / "key"
LOWER = PROFILE_DIR / "rootfs" if PROFILE else ROOT / "lower"
LOWER_BOOT = ROOT / "lower-boot"
ROLE_SETTLE_SECONDS = 25
USER = "truth"
TMPFS_SIZE = "1500M"
ACTION_TIMEOUT = 240
BOOT_TIMEOUT = 75
STOP_SECONDS = 90
SETTLE_SECONDS = 2
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}


def run(cmd, timeout=60, **kw):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=timeout, env=ENV, stdin=subprocess.DEVNULL, **kw)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except OSError as e:
        return 127, str(e)


def must(cmd, timeout=60):
    rc, out = run(cmd, timeout)
    if rc != 0:
        raise RuntimeError(f"{cmd}: {rc}: {out[-400:]}")
    return out


def prepare():
    """Binds the root read-only and builds the shared layer with the test account."""
    ROOT.mkdir(exist_ok=True)
    binds = () if PROFILE else ((LOWER, "/"), (LOWER_BOOT, "/boot"))
    for path, source in binds:
        path.mkdir(exist_ok=True)
        if run(["mountpoint", "-q", str(path)])[0] != 0:
            must(["mount", "--bind", source, str(path)])
            must(["mount", "-o", "remount,bind,ro", str(path)])
    if not KEY.exists():
        must(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(KEY)])
    if (GOLDEN / ".done").exists():
        return
    GOLDEN.mkdir(exist_ok=True)
    scratch = pathlib.Path(f"/run/ta-golden-tmp-{uuid.uuid4().hex[:8]}")
    work, merged = scratch / "work", scratch / "merged"
    work.mkdir(parents=True)
    merged.mkdir()
    must(["mount", "-t", "overlay", "overlay", "-o",
          f"lowerdir={LOWER},upperdir={GOLDEN},workdir={work}", str(merged)])
    try:
        public = (KEY.with_suffix(".pub")).read_text()
        script = f"""
set -e
useradd -m -s /bin/bash {USER}
usermod -p '*' {USER}
install -d -m 700 -o {USER} -g {USER} /home/{USER}/.ssh
printf '%s' {shlex.quote(public)} > /home/{USER}/.ssh/authorized_keys
chown {USER}:{USER} /home/{USER}/.ssh/authorized_keys
chmod 600 /home/{USER}/.ssh/authorized_keys
printf '{USER} ALL=(ALL) NOPASSWD:ALL\\n' > /etc/sudoers.d/90-truth
chmod 440 /etc/sudoers.d/90-truth
systemctl enable ssh >/dev/null 2>&1 || true
"""
        must(["systemd-nspawn", "-q", "-D", str(merged), "--private-network", "--pipe",
              "/bin/bash", "-c", script], 120)
    finally:
        run(["umount", "-l", str(merged)])
        run(["rm", "-rf", str(scratch)])
    (GOLDEN / ".done").write_text("ok\n")


class Container:
    def __init__(self):
        self.name = "ta-" + uuid.uuid4().hex[:10]
        self.dir = pathlib.Path("/run/ta-truth") / self.name
        self.merged = self.dir / "merged"
        self.proc = None
        self.leader = None

    def __enter__(self):
        # __exit__ does not run when __enter__ raises, so clean up here on failure.
        try:
            tmp = self.dir / "tmp"
            tmp.mkdir(parents=True)
            must(["mount", "-t", "tmpfs", "-o", f"size={TMPFS_SIZE},mode=755", "tmpfs", str(tmp)])
            for sub in ("upper", "work", "bupper", "bwork"):
                (tmp / sub).mkdir()
            self.merged.mkdir()
            must(["mount", "-t", "overlay", "overlay", "-o",
                  f"lowerdir={GOLDEN}:{LOWER},upperdir={tmp}/upper,workdir={tmp}/work", str(self.merged)])
            if not PROFILE:
                must(["mount", "-t", "overlay", "overlay", "-o",
                      f"lowerdir={LOWER_BOOT},upperdir={tmp}/bupper,workdir={tmp}/bwork", str(self.merged / "boot")])
        except Exception:
            self.__exit__()
            raise
        return self

    def __exit__(self, *exc):
        self.stop()
        if not PROFILE:
            run(["umount", "-l", str(self.merged / "boot")])
        run(["umount", "-l", str(self.merged)])
        run(["umount", "-l", str(self.dir / "tmp")])
        # nspawn leaves this mount behind, and thousands of them slow every later container.
        run(["umount", "-l", f"/run/systemd/nspawn/unix-export/{self.name}"])
        run(["rm", "-rf", str(self.dir)])

    def offline(self, command, timeout=ACTION_TIMEOUT):
        """Runs a command in the container's filesystem with no init running."""
        # Without -M every container takes its name from the directory, and parallel runs collide.
        # Profiles keep the host network here only, so apt can fetch replacement packages.
        network = [] if PROFILE else ["--private-network"]
        return run(["systemd-nspawn", "-q", "-D", str(self.merged), "-M", self.name, *network, "--pipe",
                    "--setenv=DEBIAN_FRONTEND=noninteractive", *command], timeout + 10)

    def boot(self):
        """Returns seconds until the container's manager settled, or None if it never did."""
        self.log = open(self.dir / "console.log", "w")
        self.proc = subprocess.Popen(
            ["systemd-nspawn", "-q", "-b", "-D", str(self.merged), "-M", self.name,
             "--private-network", "--console=pipe"],
            stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.STDOUT, env=ENV)
        start = time.monotonic()
        while time.monotonic() - start < BOOT_TIMEOUT:
            if self.proc.poll() is not None:
                return None
            rc, out = run(["systemctl", "-M", self.name, "is-system-running"], 8)
            state = out.strip().splitlines()[-1] if out.strip() else ""
            if state in ("running", "degraded", "maintenance"):
                rc, leader = run(["machinectl", "show", self.name, "-p", "Leader", "--value"], 8)
                self.leader = leader.strip()
                return time.monotonic() - start
            time.sleep(1)
        rc, leader = run(["machinectl", "show", self.name, "-p", "Leader", "--value"], 8)
        self.leader = leader.strip() if rc == 0 else None
        return None

    def stop(self):
        if self.proc and self.proc.poll() is None:
            run(["machinectl", "terminate", self.name], 15)
            try:
                # ubu24's services take 31 s to stop. nspawn killed early leaves a mount that refuses the next boot.
                self.proc.wait(STOP_SECONDS)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(5)
        if self.proc:
            # A container that asked to reboot comes back under the same name and outlives nspawn being killed.
            run(["machinectl", "terminate", self.name], 15)
            self.log.close()

    def inside(self, *command, timeout=20):
        if not self.leader:
            return 125, "no leader"
        return run(["nsenter", "-t", self.leader, "-a", "--", *command], timeout)

    def ssh(self, *command, timeout=20):
        if not self.leader:
            return 125, "no leader"
        return run(["nsenter", "-t", self.leader, "-n", "--", "ssh", "-i", str(KEY),
                    "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                    "-o", "ConnectTimeout=6", "-o", "BatchMode=yes", "-o", "LogLevel=ERROR",
                    f"{USER}@127.0.0.1", *command], timeout)

    def state_of(self, unit):
        rc, out = run(["systemctl", "-M", self.name, "is-active", unit], 8)
        return out.strip().splitlines()[-1] if out.strip() else ""


def tcp_exchange(port, send=b"", family=socket.AF_INET, host="127.0.0.1"):
    """Returns what a TCP service answers. Runs in the container's network namespace."""
    code = ("import socket,sys\n"
            f"s=socket.create_connection(({host!r},{port}),timeout=4)\n"
            f"s.sendall({send!r})\n"
            "s.settimeout(4)\n"
            "sys.stdout.write(s.recv(512).decode('latin-1'))\n")
    return code


def smb_negotiate():
    dialects = b"".join(b"\x02" + d + b"\x00" for d in (b"NT LM 0.12", b"SMB 2.002", b"SMB 2.???"))
    header = b"\xffSMB\x72" + bytes(4) + b"\x18\x01\x28" + bytes(20)
    body = header + b"\x00" + len(dialects).to_bytes(2, "little") + dialects
    return len(body).to_bytes(4, "big") + body


SMB_NEGOTIATE = smb_negotiate()

# Each role must answer its own protocol. A listening socket alone is not enough.
ROLE_PROBES = {
    "http": (80, b"GET / HTTP/1.0\r\n\r\n", "HTTP/1."),
    "php": (80, b"GET /probe.php HTTP/1.0\r\n\r\n", "php-works"),
    "postgres": (5432, bytes.fromhex("0000000804d2162f"), ("S", "N")),
    "mariadb": (3306, b"", "mysql_native_password"),
    "redis": (6379, b"PING\r\n", "+PONG"),
    "smtp": (25, b"", "220 "),
    "imap": (143, b"", "* OK"),
    "dns": (53, bytes.fromhex("001d0001010000010000000000000776657273696f6e0462696e640000100003"), ""),
    "smb": (445, SMB_NEGOTIATE, "SMB"),
    "memcached": (11211, b"version\r\n", "VERSION"),
    "mqtt": (1883, bytes.fromhex("101000044d5154540402003c0004746573"[:34]) + b"t", " "),
    "squid": (3128, b"GET cache_object://localhost/info HTTP/1.0\r\n\r\n", "HTTP/1."),
    "ftp": (21, b"", "220"),
    "cups": (631, b"GET / HTTP/1.0\r\n\r\n", "HTTP/1."),
    "ldap": (389, bytes.fromhex("300c020101600702010304008000"), "0"),
}


def probe_role(c, role):
    port, send, expect = ROLE_PROBES[role]
    code = tcp_exchange(port, send)
    rc, out = run(["nsenter", "-t", c.leader, "-n", "--", "python3", "-c", code], 12) if c.leader else (125, "")
    if rc != 0 or not out:
        return False
    return any(e in out for e in ((expect,) if isinstance(expect, str) else expect))


def role_checks(c, booted):
    """Returns role -> answering. Services get time to come up before a failure counts."""
    if not PROFILE or booted is None:
        roles = PROFILE_DIR and (PROFILE_DIR / "roles.txt").read_text().split()
        return {r: False for r in roles or ()}
    roles = (PROFILE_DIR / "roles.txt").read_text().split()
    result, deadline = {}, time.monotonic() + ROLE_SETTLE_SECONDS
    while True:
        for role in roles:
            if not result.get(role):
                result[role] = probe_role(c, role)
        if all(result.values()) or time.monotonic() > deadline:
            return result
        time.sleep(3)


def checks(c, booted):
    """Each value is True when the capability still works."""
    merged = c.merged
    result = {
        "boot": booted is not None,
        "multi_user": booted is not None and c.state_of("multi-user.target") == "active",
        "ssh_login": c.ssh("true")[0] == 0,
        "sudo": c.ssh("sudo", "-n", "true")[0] == 0,
        "apt": c.inside("apt-get", "check")[0] == 0,
        "dpkg": c.inside("dpkg", "--audit")[0] == 0,
        "shell": c.inside("/bin/sh", "-c", "exit 0")[0] == 0,
        "dbus": c.inside("busctl", "--no-pager", "list")[0] == 0,
        "journal": c.inside("journalctl", "-n", "1", "--no-pager")[0] == 0,
        "boot_files": bool(list((merged / "boot").glob("vmlinuz-*")))
        and bool(list((merged / "boot").glob("initrd.img-*")))
        and (merged / "boot/grub/grub.cfg").exists(),
        "net_config": (merged / "usr/sbin/netplan").exists()
        and (merged / "usr/lib/systemd/systemd-networkd").exists(),
        "lvm_tools": (merged / "usr/sbin/lvm").exists(),
    }
    result.update({f"role_{k}": v for k, v in role_checks(c, booted).items()})
    return result


def case_remove(package):
    with Container() as c:
        start = time.monotonic()
        rc, out = c.offline(["apt-get", "-y", "--allow-remove-essential", "remove", package])
        removed = [line.split()[1].split(":")[0] for line in out.splitlines() if line.startswith("Removing ")]
        action = {"rc": rc, "seconds": round(time.monotonic() - start, 1),
                  "removed": removed, "tail": out[-1500:] if rc else ""}
        booted = c.boot()
        time.sleep(SETTLE_SECONDS)
        return action, booted, checks(c, booted)


def case_service(verb, unit):
    with Container() as c:
        booted = c.boot()
        before = c.state_of(unit)
        start = time.monotonic()
        rc, out = run(["systemctl", "-M", c.name, verb, unit], 60)
        action = {"rc": rc, "seconds": round(time.monotonic() - start, 1), "before": before,
                  "after": "", "tail": out[-300:] if rc else ""}
        time.sleep(SETTLE_SECONDS)
        action["after"] = c.state_of(unit)
        return action, booted, checks(c, booted)


def collect_facts():
    """Records what a decision could read on this machine, with its services running."""
    with Container() as c:
        booted = c.boot()
        time.sleep(ROLE_SETTLE_SECONDS // 2)
        code = """
import glob, json, os, subprocess
procs = []
for pid in filter(str.isdigit, os.listdir("/proc")):
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
        maps = {l.split(None, 5)[5].strip() for l in open(f"/proc/{pid}/maps") if len(l.split(None, 5)) > 5}
        procs.append({"exe": exe, "maps": sorted(m for m in maps if m.startswith("/"))})
    except OSError:
        pass
lists = {}
for p in glob.glob("/var/lib/dpkg/info/*.list"):
    n = os.path.basename(p)[:-5].split(":")[0]
    lists[n] = [l.strip() for l in open(p, errors="replace") if l.strip() and not os.path.isdir(l.strip())]
ss = subprocess.run(["ss", "-ltnupH"], capture_output=True, text=True).stdout
pam = {}
for p in glob.glob("/etc/pam.d/*"):
    pam[os.path.basename(p)] = open(p, errors="replace").read()
print(json.dumps({"procs": procs, "lists": lists, "ss": ss, "pam": pam}))
"""
        rc, out = c.inside("python3", "-c", code, timeout=60)
        if rc != 0:
            raise RuntimeError(out[-500:])
        facts = json.loads(out)
        rc, out = run(["systemctl", "-M", c.name, "list-unit-files", "--type=service", "--no-legend", "--no-pager"], 20)
        names = sorted({line.split()[0][:-len(".service")] for line in out.splitlines()
                        if line.split() and line.split()[0].endswith(".service") and "@" not in line.split()[0]})
        units = {}
        for unit in names:
            rc, show = run(["systemctl", "-M", c.name, "show", unit], 10)
            props = dict(x.split("=", 1) for x in show.splitlines() if "=" in x)
            path = props.get("FragmentPath", "").lstrip("/")
            target = c.merged / path if path else None
            props["_text"] = target.read_text(errors="replace")[:4000] if target and target.is_file() else ""
            units[unit] = props
        facts["units"] = units
        facts["status"] = (c.merged / "var/lib/dpkg/status").read_text(errors="replace")
        facts["checks"] = checks(c, booted)
        return facts


def write_cases(facts, path):
    packages = [b.split("\n", 1)[0][9:] for b in facts["status"].split("\n\n")
                if b.startswith("Package: ") and "Status: install ok installed" in b]
    lines = [f"remove {p}" for p in sorted(packages)]
    lines += [f"{verb} {u}" for u in sorted(facts["units"]) for verb in ("stop", "restart")]
    pathlib.Path(path).write_text("\n".join(lines) + "\n")
    return len(lines)


def run_case(case):
    kind = case[0]
    started = time.monotonic()
    try:
        if kind == "baseline":
            action, booted, result = case_service("is-active", "multi-user.target")
        elif kind == "remove":
            action, booted, result = case_remove(case[1])
        elif kind in ("stop", "restart"):
            action, booted, result = case_service(kind, case[1])
        else:
            raise ValueError(kind)
        return {"case": case, "action": action, "boot_seconds": booted and round(booted, 1),
                "checks": result, "total_seconds": round(time.monotonic() - started, 1)}
    except Exception as e:
        return {"case": case, "error": str(e)[-500:]}


def collect_plans(packages):
    """Asks this machine's own apt what each removal would do, changing nothing."""
    code = f"""
import json, re, subprocess
plans = {{}}
for package in {json.dumps(packages)}:
    p = subprocess.run(["apt-get", "-s", "--allow-remove-essential", "remove", package],
                       capture_output=True, text=True, errors="replace")
    plans[package] = {{"rc": p.returncode, "removes": re.findall(r"^Remv (\\S+)", p.stdout, re.M),
                      "installs": re.findall(r"^Inst (\\S+)", p.stdout, re.M)}}
print(json.dumps(plans))
"""
    with Container() as c:
        rc, out = c.offline(["python3", "-c", code], timeout=3600)
        if rc != 0:
            raise RuntimeError(out[-500:])
        return json.loads(out.strip().splitlines()[-1])


def main():
    if os.geteuid() != 0 or os.environ.get("TRUSTAUTO_TRUTH_DISPOSABLE") != "yes":
        sys.exit("run as root with TRUSTAUTO_TRUTH_DISPOSABLE=yes, in a disposable VM only")
    prepare()
    pathlib.Path("/run/ta-truth").mkdir(exist_ok=True)
    args = sys.argv[1:]
    if args[0] == "collect":
        facts = collect_facts()
        pathlib.Path(args[1]).write_text(json.dumps(facts))
        print(len(facts["procs"]), "processes", write_cases(facts, args[2]), "cases",
              "failed checks:", [k for k, v in facts["checks"].items() if not v])
    elif args[0] == "plans":
        cases = [line.split() for line in pathlib.Path(args[1]).read_text().splitlines() if line.strip()]
        pathlib.Path(args[2]).write_text(json.dumps(collect_plans([c[1] for c in cases if c[0] == "remove"])))
    elif args[0] == "baseline":
        print(json.dumps(run_case(["baseline"]), indent=1))
    elif args[0] == "case":
        print(json.dumps(run_case(args[1:]), indent=1))
    elif args[0] == "batch":
        workers = int(args[4]) if len(args) > 4 else 3
        cases = [line.split() for line in pathlib.Path(args[1]).read_text().splitlines() if line.strip()]
        out = pathlib.Path(args[2])
        done = set()
        if out.exists():
            done = {" ".join(json.loads(line)["case"]) for line in out.read_text().splitlines()}
        todo = [c for c in cases if " ".join(c) not in done]
        print(f"{len(todo)} to run, {len(done)} already done", flush=True)
        with open(out, "a") as sink, concurrent.futures.ThreadPoolExecutor(workers) as pool:
            for i, result in enumerate(pool.map(run_case, todo), 1):
                sink.write(json.dumps(result) + "\n")
                sink.flush()
                if i % 25 == 0:
                    print(f"{i}/{len(todo)}", flush=True)


if __name__ == "__main__":
    main()
