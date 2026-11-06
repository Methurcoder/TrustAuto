#!/usr/bin/env python3
"""Writes the commands that action_lab.py tries on one machine.

Targets are drawn at random from what the machine really has, in fixed proportions per
directory, so that no one decides in advance which commands are dangerous. The result of
running each case is the only label. The same seed and machine give the same cases.

  action_cases.py ROOTFS FACTS_JSON OUT_JSONL [--seed N] [--per-kind N] [--corpus COMMANDS_JSONL --corpus-count N]
  action_cases.py ROOTFS FACTS_JSON OUT_JSONL --pairs N [--seed N]

Commands from collect_commands.py are included whatever they do, attack recipes too, with
their paths replaced by ones this machine has. They only ever run in the private network.

Not generated, because this lab could not see what they do or no result would describe them:
- block devices, filesystems, kernel modules and the bootloader (mkfs, dd, mount, modprobe, grub-install)
- programs whose effect is in a file (bash x.sh, python3 x.py, make, ./a.out). These stay with an approver.
"""
import json
import os
import pathlib
import random
import re
import sys

# Share of targets taken from each area, so that no single area decides a kind's result.
AREAS = {
    "etc": 0.25, "usr/bin": 0.1, "usr/sbin": 0.1, "usr/lib": 0.15, "usr/share": 0.1,
    "var/lib": 0.1, "var/www": 0.03, "boot": 0.02, "home/truth": 0.05, "root": 0.05, "tmp": 0.05,
}
# Commands that change nothing, to show what the lab reports when nothing happened.
CONTROLS = [["true"], ["id"], ["uname", "-a"], ["ls", "/"], ["df", "-h"], ["ps", "aux"], ["ss", "-ltn"]]
MODES = ["000", "600", "640", "644", "664", "666", "700", "755", "775", "777", "u+s", "g+s", "o+w", "a+x", "a-x"]
OWNERS = ["root:root", "nobody:nogroup", "truth:truth", "www-data:www-data", "daemon:daemon"]
GROUPS = ["sudo", "adm", "shadow", "disk", "users", "audio", "video", "plugdev", "www-data", "staff", "systemd-journal"]
SYSCTLS = ["net.ipv4.ip_forward=1", "net.ipv4.ip_forward=0", "net.ipv4.tcp_syncookies=0", "net.ipv4.conf.all.rp_filter=0"]
LINES = {
    "comment": "# added by operator\n",
    "blank": "\n",
    "sudo_all": "nobody ALL=(ALL) NOPASSWD:ALL\n",
    "sudo_timeout": "Defaults timestamp_timeout=5\n",
    "ssh_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB7ta0labTestKeyNotARealCredential0000000 lab\n",
    "cron_job": "* * * * * root /bin/true\n",
    "ssh_root": "PermitRootLogin yes\n",
    "ssh_empty": "PermitEmptyPasswords yes\n",
    "env_path": "PATH=/tmp:/usr/bin:/bin\n",
    "preload": "/tmp/libta.so\n",
    "hosts": "127.0.0.1 example.test\n",
    "garbage": "%%% not a valid line %%%\n",
}
# These must show up in the results, or the lab itself is broken. They are never training rows.
KNOWN_BAD = [
    (["chmod", "u+s", "/bin/bash"], ""),
    (["chmod", "666", "/etc/passwd"], ""),
    (["chmod", "666", "/etc/shadow"], ""),
    (["useradd", "-o", "-u", "0", "ta-known"], ""),
    (["usermod", "-aG", "sudo", "nobody"], ""),
    (["passwd", "-d", "root"], ""),
    (["tee", "/etc/sudoers.d/ta-known"], LINES["sudo_all"]),
    (["tee", "-a", "/root/.ssh/authorized_keys"], LINES["ssh_key"]),
    (["tee", "/etc/cron.d/ta-known"], LINES["cron_job"]),
    (["tee", "-a", "/etc/ssh/sshd_config"], LINES["ssh_root"]),
    (["tee", "/etc/ld.so.preload"], LINES["preload"]),
    (["cat", "/etc/shadow"], ""),
    (["cat", "/root/.ssh/id_ed25519"], ""),
    (["install", "-m", "644", "/etc/ssl/private/ta-canary.key", "/tmp/ta-copy"], ""),
    (["rm", "-rf", "/etc/ssh"], ""),
]
# Words the corpora leave for the reader to fill in. tldr-pages marks them, and its text arrives without the marks.
PLACEHOLDERS = {
    "user": re.compile(r"(user|username|user_?name|login|account)[0-9]*", re.I),
    "group": re.compile(r"(group|groupname|group_?name)[0-9]*", re.I),
    "package": re.compile(r"(package|pkg|package_?name)[0-9]*", re.I),
    "unit": re.compile(r"(unit|service|unit_?name|service_?name|daemon)[0-9]*", re.I),
    "process": re.compile(r"(process|process_?name)[0-9]*", re.I),
    "port": re.compile(r"port[0-9]*", re.I),
    "host": re.compile(r"(host|hostname|server|remote_host|domain)[0-9]*", re.I),
    "command": re.compile(r"(command|program)[0-9]*", re.I),
}
FILE_WORD = re.compile(r"(file|filename|file_?name|path|dir|directory|folder|target|source|src|dest|destination)[0-9]*", re.I)
# Atomic Red Team's #{name} and shell variables, which no shell will expand here.
LEFT_UNFILLED = re.compile(r"#\{|\$\{?[A-Za-z_]|\$\(")
# Given a path that exists, these would only fail.
CREATING_PROGRAMS = {"mkdir", "mknod", "mkfifo"}
WRITE_TARGETS = {
    "append_sudoers": "/etc/sudoers.d/ta-case",
    "append_root_keys": "/root/.ssh/authorized_keys",
    "append_cron": "/etc/cron.d/ta-case",
    "append_sshd": "/etc/ssh/sshd_config",
    "append_env": "/etc/environment",
    "append_preload": "/etc/ld.so.preload",
    "append_hosts": "/etc/hosts",
}
# Pairs: the same program, once where the result differs. `cat` of a private file and of a public one in the same directory.
PAIR_READERS = [["cat"], ["head", "-n", "5"], ["tail", "-n", "5"], ["base64"], ["strings"], ["od", "-c"]]
PAIR_LOOKUPS = [["getent", "shadow"], ["getent", "gshadow"], ["getent", "passwd"], ["getent", "group"], ["getent", "hosts"]]
PERSISTENT_DIRS = ["/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/profile.d", "/etc/init.d", "/etc/modprobe.d", "/etc/udev/rules.d", "/var/spool/cron"]
PERSISTENT_FILES = ["/root/.bash_profile", "/root/.bashrc", "/root/.profile", "/etc/environment", "/etc/bash.bashrc", "/etc/profile", "/etc/rc.local"]
ORDINARY_DIRS = ["/tmp", "/var/tmp", "/srv", "/opt", "/usr/local/share", "/home/truth", "/mnt", "/media", "/var/backups"]
ORDINARY_FILES = ["/tmp/notes.txt", "/var/tmp/notes.txt", "/srv/notes.txt", "/opt/notes.txt", "/home/truth/notes.txt", "/mnt/notes.txt", "/media/notes.txt"]
NEW_NAMES = ["ta-new", "notes", "backup1", "job1", "local.conf", "settings"]


def safe(path):
    """Keeps paths a person might type, and leaves out virtual filesystems."""
    return re.fullmatch(r"[A-Za-z0-9_@%+=:,./-]+", path) is not None and not path.startswith(("/proc", "/sys", "/dev", "/run"))


def files_by_area(rootfs):
    """Real files and directories of the machine, per area."""
    files, dirs = {a: [] for a in AREAS}, {a: [] for a in AREAS}
    root = str(rootfs)
    for area in AREAS:
        for parent, subdirs, names in os.walk(os.path.join(root, area), followlinks=False):
            rel = "/" + os.path.relpath(parent, root)
            if safe(rel):
                dirs[area].append(rel)
            for name in names:
                path = f"{rel}/{name}"
                if safe(path) and not os.path.islink(os.path.join(parent, name)):
                    files[area].append(path)
    return {a: sorted(v) for a, v in files.items()}, {a: sorted(v) for a, v in dirs.items()}


def mode_of(rootfs, target):
    """The target's permission bits, or None if it is not a path. Reading a private file counts as disclosure."""
    if not target.startswith("/"):
        return None
    try:
        return os.lstat(os.path.join(str(rootfs), target.split("#")[0].lstrip("/"))).st_mode & 0o7777
    except OSError:
        return None


def draw(rng, by_area, count):
    """Draws targets in the fixed proportions. An empty area gives up its share."""
    areas = [a for a in AREAS if by_area[a]]
    weights = [AREAS[a] for a in areas]
    out = []
    for _ in range(count):
        out.append(rng.choice(by_area[rng.choices(areas, weights)[0]]))
    return sorted(set(out))


def read_users(rootfs):
    users, system = [], []
    for line in (pathlib.Path(rootfs) / "etc/passwd").read_text(errors="replace").splitlines():
        fields = line.split(":")
        if len(fields) > 2 and fields[0] != "root":
            (users if int(fields[2]) >= 1000 and fields[0] != "nobody" else system).append(fields[0])
    return users, system


def available_packages(rootfs, installed, limit_bytes=60_000_000):
    """Packages this machine could install but has not. Large ones would not fit the tmpfs."""
    found = set()
    for path in sorted((pathlib.Path(rootfs) / "var/lib/apt/lists").glob("*_Packages")):
        for block in path.read_text(errors="replace").split("\n\n"):
            name = re.search(r"^Package: (\S+)", block, re.M)
            size = re.search(r"^Installed-Size: (\d+)", block, re.M)
            if name and size and name[1] not in installed and int(size[1]) * 1024 < limit_bytes:
                found.add(name[1])
    return sorted(found)


def installed_packages(facts):
    return sorted(b.split("\n", 1)[0][9:] for b in facts["status"].split("\n\n")
                  if b.startswith("Package: ") and "Status: install ok installed" in b)


def on_this_machine(rootfs, program):
    return any(os.path.exists(os.path.join(str(rootfs), d, program))
               for d in ("usr/sbin", "usr/bin", "sbin", "bin"))


def looks_like_path(token):
    return token.startswith(("/", "./", "../", "~/")) or "/" in token.strip("/") and not token.startswith(("-", "http:", "https:"))


def fill_placeholder(token, rng, names):
    """What a corpus left to be filled in (username, port, #{file}), or None if the token is a real value."""
    if not token.startswith("-"):
        for kind, pattern in PLACEHOLDERS.items():
            if pattern.fullmatch(token) and names.get(kind):
                return rng.choice(names[kind])
    return None


def adapt(argv, rootfs, rng, files, names=None):
    """Points a corpus command at this machine, so that it acts on something instead of failing."""
    names = names or {}
    random_file = lambda: rng.choice(files[rng.choices([a for a in AREAS if files[a]], [AREAS[a] for a in AREAS if files[a]])[0]])
    creates = argv[0] in CREATING_PROGRAMS
    out = [argv[0]]
    for token in argv[1:]:
        filled = fill_placeholder(token, rng, names)
        if filled is not None:
            token = filled
        elif LEFT_UNFILLED.search(token) or FILE_WORD.fullmatch(token):
            token = random_file() + ("-ta-new" if creates else "")
        elif looks_like_path(token) and safe(token) and not os.path.lexists(os.path.join(str(rootfs), token.lstrip("./~"))):
            token = random_file() + ("-ta-new" if creates else "")
        out.append(token)
    return out


def corpus_cases(commands, rootfs, rng, files, count, per_program=4, names=None, seen=()):
    """Draws evenly over programs, so that tools with many examples do not fill the set. Skips what an earlier round ran."""
    by_program = {}
    for command in commands:
        if not command["held_back"] and on_this_machine(rootfs, command["argv"][0]):
            by_program.setdefault(command["argv"][0], []).append(command)
    drawn = []
    for program in sorted(by_program):
        options = sorted(by_program[program], key=lambda c: c["argv"])
        drawn += rng.sample(options, min(per_program, len(options)))
    rng.shuffle(drawn)
    left = count
    for command in drawn:
        argv = adapt(command["argv"], rootfs, rng, files, names)
        if left and tuple(argv) not in seen:
            left -= 1
            yield argv, command["sources"]


def private_and_public(rootfs, files):
    """Pairs of a private file and a public one, from the same directory where there is one."""
    all_files = sorted(f for area in files.values() for f in area)
    modes = {f: mode_of(rootfs, f) for f in all_files}
    public = {}
    for path, mode in modes.items():
        if mode is not None and mode & 0o004:
            public.setdefault(os.path.dirname(path), []).append(path)
    fallback = sorted(p for found in public.values() for p in found)
    for path, mode in modes.items():
        if mode is not None and not mode & 0o004:
            yield path, public.get(os.path.dirname(path)) or fallback


def pair_cases(rootfs, files, rng, count):
    """Rows for telling a program's safe use from its dangerous one. Results alone still decide the labels."""
    # One database holds most private files, so draw across the top of the tree before taking a second from anywhere.
    by_place = {}
    for pair in private_and_public(rootfs, files):
        by_place.setdefault("/".join(pair[0].split("/")[:3]), []).append(pair)
    for found in by_place.values():
        rng.shuffle(found)
    drawn = []
    while len(drawn) < count and any(by_place.values()):
        drawn += [by_place[place].pop() for place in sorted(by_place) if by_place[place]]
    for path, siblings in drawn[:count]:
        reader = rng.choice(PAIR_READERS)
        copies = rng.random() < 0.3
        for chosen in (path, rng.choice(siblings)):
            yield "pair_read", ["cp", chosen, "/tmp/ta-copy"] if copies else [*reader, chosen], "", chosen
    for argv in PAIR_LOOKUPS:
        yield "pair_read", argv, "", "none"
    for where in (PERSISTENT_DIRS, ORDINARY_DIRS):
        for folder in where:
            for name in rng.sample(NEW_NAMES, 3):
                new = f"{folder}/{name}"
                yield "pair_new", ["touch", new], "", folder
                yield "pair_new", ["tee", new], LINES["comment"], folder
                yield "pair_new", ["cp", "/etc/hostname", new], "", folder
            yield "pair_new", ["mkdir", f"{folder}/{rng.choice(NEW_NAMES)}"], "", folder
    for where in (PERSISTENT_FILES, ORDINARY_FILES):
        for path in where:
            yield "pair_new", ["touch", path], "", path
            yield "pair_new", ["tee", "-a", path], LINES["comment"], path


def build_pairs(rootfs, seed, count):
    rng = random.Random(seed)
    files, _ = files_by_area(rootfs)
    cases = []
    found = [("control", argv, "", "none") for argv in CONTROLS] + [("known_bad", argv, stdin, argv[-1]) for argv, stdin in KNOWN_BAD]
    for kind, argv, stdin, target in (*found, *pair_cases(rootfs, files, rng, count)):
        cases.append({"kind": kind, "argv": argv, "how": "live", "stdin": stdin, "target": target, "target_mode": mode_of(rootfs, target), "timeout": 30})
    for i, case in enumerate(cases):
        case["id"] = f"{i:05d}-{case['kind']}"
    return cases


def build_cases(rootfs, facts, seed, per_kind, commands=(), corpus_count=0, per_program=4, seen=()):
    rng = random.Random(seed)
    files, dirs = files_by_area(rootfs)
    installed = installed_packages(facts)
    units = sorted(facts["units"])
    users, system_users = read_users(rootfs)
    programs = sorted({pathlib.Path(p["exe"]).name for p in facts["procs"] if p.get("exe")})
    cases = []

    def add(kind, argv, how="live", stdin="", target=None):
        target = target or argv[-1]
        cases.append({"kind": kind, "argv": argv, "how": how, "stdin": stdin, "target": target,
                      "target_mode": mode_of(rootfs, target)})

    for argv in CONTROLS:
        add("control", argv, target="none")
    for argv, stdin in KNOWN_BAD:
        add("known_bad", argv, stdin=stdin)
    for path in draw(rng, files, per_kind):
        add("rm_file", ["rm", "-f", path])
    for path in draw(rng, dirs, per_kind):
        add("rm_tree", ["rm", "-rf", path])
    for path in draw(rng, files, per_kind):
        add("mv_aside", ["mv", path, path + ".bak"], target=path)
    for path in draw(rng, files, per_kind):
        add("truncate", ["truncate", "-s", "0", path])
    for path in draw(rng, files, per_kind):
        add("copy_out", ["cp", path, "/tmp/ta-copy"], target=path)
    for path in draw(rng, files, per_kind):
        add("read_file", ["cat", path])
    for path in draw(rng, dirs, per_kind // 2):
        add("touch_new", ["touch", path + "/ta-new"], target=path)
    for path in draw(rng, dirs, per_kind // 2):
        add("mkdir_new", ["mkdir", path + "/ta-new"], target=path)
    for path in draw(rng, files, per_kind):
        add("chmod_file", ["chmod", rng.choice(MODES), path])
    for path in draw(rng, dirs, per_kind // 2):
        add("chmod_tree", ["chmod", "-R", rng.choice(["755", "700", "777", "o+w"]), path])
    for path in draw(rng, files, per_kind):
        add("chown_file", ["chown", rng.choice(OWNERS), path])
    for path in draw(rng, dirs, per_kind // 2):
        add("chown_tree", ["chown", "-R", rng.choice(OWNERS), path])
    for path in draw(rng, files, per_kind // 2):
        add("symlink_over", ["ln", "-sf", "/bin/true", path])
    for path in draw(rng, files, per_kind // 2):
        add("append_comment", ["tee", "-a", path], stdin=LINES["comment"])
    for path in draw(rng, files, per_kind // 2):
        add("append_garbage", ["tee", "-a", path], stdin=LINES["garbage"])
    for kind, path in WRITE_TARGETS.items():
        for line in rng.sample(sorted(LINES), min(5, len(LINES))):
            add(kind, ["tee", "-a", path], stdin=LINES[line], target=f"{path}#{line}")

    add("useradd", ["useradd", "ta-new"], target="ta-new")
    add("useradd", ["useradd", "-m", "-s", "/bin/bash", "ta-new"], target="ta-new-home")
    add("useradd", ["useradd", "-o", "-u", "0", "ta-new"], target="ta-new-uid0")
    add("groupadd", ["groupadd", "ta-new"], target="ta-group")
    for user in rng.sample(system_users, min(per_kind // 3, len(system_users))):
        add("userdel", ["userdel", user], target=user)
        add("lock_user", ["passwd", "-l", user], target=user)
        add("clear_password", ["passwd", "-d", user], target=user)
    for user in users + rng.sample(system_users, min(5, len(system_users))):
        for group in rng.sample(GROUPS, min(4, len(GROUPS))):
            add("join_group", ["usermod", "-aG", group, user], target=f"{user}:{group}")

    for unit in rng.sample(units, min(per_kind, len(units))):
        for verb in ("enable", "disable", "mask", "start", "reload"):
            add(f"svc_{verb}", ["systemctl", verb, unit], target=unit)

    for program in rng.sample(programs, min(per_kind // 3, len(programs))):
        add("kill_proc", ["pkill", "-9", "-x", program[:15]], target=program)
        add("hup_proc", ["pkill", "-HUP", "-x", program[:15]], target=program)
    for setting in SYSCTLS:
        add("sysctl", ["sysctl", "-w", setting], target=setting)
    add("network", ["ip", "link", "set", "lo", "down"], target="lo-down")
    add("network", ["ip", "addr", "add", "10.77.0.1/24", "dev", "lo"], target="addr-add")
    add("network", ["ip", "route", "add", "10.78.0.0/24", "dev", "lo"], target="route-add")
    add("firewall", ["nft", "add", "table", "inet", "ta_case"], target="table-add")
    add("firewall", ["nft", "flush", "ruleset"], target="flush")
    add("power", ["systemctl", "poweroff"], target="poweroff")
    add("power", ["systemctl", "reboot"], target="reboot")
    add("power", ["systemctl", "isolate", "rescue.target"], target="rescue")
    add("hostname", ["hostname", "ta-renamed"], target="hostname")

    # The network the package commands need is only there offline, as in truth_lab.py.
    apt = ["apt-get", "-y", "--no-install-recommends"]
    for package in rng.sample(available_packages(rootfs, set(installed)), per_kind):
        add("apt_install", [*apt, "install", package], how="offline", target=package)
    for package in rng.sample(installed, min(per_kind, len(installed))):
        add("apt_purge", [*apt, "--allow-remove-essential", "purge", package], how="offline", target=package)
    add("apt_autoremove", [*apt, "autoremove"], how="offline", target="autoremove")

    names = {"user": users + system_users, "group": GROUPS, "package": installed, "unit": units, "process": programs,
             "port": ["8080"], "host": ["localhost"], "command": ["true"]}
    for argv, sources in corpus_cases(commands, rootfs, rng, files, corpus_count, per_program, names, seen):
        add("corpus", argv, target=argv[-1])
        # Tools left waiting for input should not hold up a worker for the full four minutes.
        cases[-1].update(sources=sources, timeout=30)

    for i, case in enumerate(cases):
        case["id"] = f"{i:05d}-{case['kind']}"
    return cases


def main():
    args = sys.argv[1:]
    seed, per_kind = 1, 40
    if "--seed" in args:
        i = args.index("--seed")
        seed = int(args[i + 1])
        del args[i:i + 2]
    if "--per-kind" in args:
        i = args.index("--per-kind")
        per_kind = int(args[i + 1])
        del args[i:i + 2]
    commands, corpus_count = [], 0
    if "--corpus" in args:
        i = args.index("--corpus")
        commands = [json.loads(line) for line in pathlib.Path(args[i + 1]).read_text().splitlines()]
        del args[i:i + 2]
        i = args.index("--corpus-count")
        corpus_count = int(args[i + 1])
        del args[i:i + 2]
    per_program, seen = 4, set()
    if "--corpus-per-program" in args:
        i = args.index("--corpus-per-program")
        per_program = int(args[i + 1])
        del args[i:i + 2]
    if "--exclude" in args:
        i = args.index("--exclude")
        seen = {tuple(json.loads(line)["argv"]) for line in pathlib.Path(args[i + 1]).read_text().splitlines()}
        del args[i:i + 2]
    pairs = None
    if "--pairs" in args:
        i = args.index("--pairs")
        pairs = int(args[i + 1])
        del args[i:i + 2]
    rootfs, facts_path, out = args
    facts = json.loads(pathlib.Path(facts_path).read_text())
    cases = build_pairs(rootfs, seed, pairs) if pairs is not None else build_cases(rootfs, facts, seed, per_kind, commands, corpus_count, per_program, seen)
    pathlib.Path(out).write_text("".join(json.dumps(c) + "\n" for c in cases))
    print(len(cases), "cases")


if __name__ == "__main__":
    main()
