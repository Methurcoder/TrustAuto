#!/usr/bin/env python3
"""Records who uses what on a machine image: library links, interpreters, and names used in text.

  collect_usage.py ROOTFS OUT_JSON

Only reads. It walks real directories and never follows a symlink, so an absolute link in
the image cannot lead it out onto the machine it runs on.
"""
import json
import os
import re
import stat
import subprocess
import sys

TOP_LEVELS = ("usr", "etc", "opt", "lib", "lib64", "bin", "sbin", "var/lib/dpkg/info")
SKIP = ("/usr/share/doc/", "/usr/share/man/", "/usr/share/locale/", "/usr/share/info/", "/usr/include/",
        "/usr/share/zoneinfo/", "/usr/share/i18n/", "/usr/share/perl/", "/usr/lib/python3", "/usr/share/mime/")
COMMAND_DIRS = ("/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/", "/usr/games/", "/bin/", "/sbin/")
UNIT_DIRS = ("/usr/lib/systemd/system/", "/lib/systemd/system/", "/etc/systemd/system/")
TEXT_LIMIT = 512 * 1024
WORD = re.compile(rb"[A-Za-z0-9_.+-]{2,}")
PATH = re.compile(rb"/[A-Za-z0-9_.+/-]{2,}")
NEEDED = re.compile(r"\(NEEDED\).*\[(.+)\]")


def walk(root):
    for top in TOP_LEVELS:
        start = os.path.join(root, top)
        if os.path.islink(start) or not os.path.isdir(start):
            continue
        for folder, subfolders, names in os.walk(start, followlinks=False):
            for name in names:
                full = os.path.join(folder, name)
                yield "/" + os.path.relpath(full, root), full


def is_scanned(path, mode):
    if path.startswith(SKIP):
        return False
    return path.startswith(("/etc/", "/var/lib/dpkg/info/", "/usr/lib/systemd/", "/lib/systemd/")) or bool(mode & 0o111)


def main():
    root, out = sys.argv[1], sys.argv[2]
    entries = []
    links, names = {}, set()
    for path, full in walk(root):
        info = os.lstat(full)
        if stat.S_ISLNK(info.st_mode):
            links[path] = os.readlink(full)
        elif not stat.S_ISREG(info.st_mode):
            continue
        else:
            entries.append((path, full, info.st_mode, info.st_size))
        base = path.rsplit("/", 1)[1]
        if path.startswith(COMMAND_DIRS):
            names.add(base.encode())
        if path.startswith(UNIT_DIRS) and base.endswith(".service"):
            names.add(base.encode())
            names.add(base[:-len(".service")].encode())
    known_paths = {e[0].encode() for e in entries} | {p.encode() for p in links}

    needed, interp, refs = {}, {}, {}
    for path, full, mode, size in entries:
        if path.startswith(SKIP) or size < 4:
            continue
        with open(full, "rb") as stream:
            head = stream.read(TEXT_LIMIT if is_scanned(path, mode) else 4)
            if head[:4] == b"\x7fELF":
                shown = subprocess.run(["readelf", "-d", "--wide", full], capture_output=True, text=True, errors="replace")
                libraries = NEEDED.findall(shown.stdout)
                if libraries:
                    needed[path] = libraries
                continue
            if not is_scanned(path, mode) or b"\0" in head[:8192]:
                continue
        if head.startswith(b"#!"):
            words = head[2:].split(b"\n", 1)[0].split()
            if words:
                interp[path] = [w.decode(errors="replace") for w in words[:2]]
        found = {w for w in WORD.findall(head) if w in names} | {p for p in PATH.findall(head) if p in known_paths}
        found.discard(path.rsplit("/", 1)[1].encode())
        if found:
            refs[path] = sorted(w.decode() for w in found)

    with open(out, "w") as stream:
        json.dump({"links": links, "needed": needed, "interp": interp, "refs": refs}, stream)
    print(f"{len(entries)} files, {len(links)} links, {len(needed)} with libraries, {len(interp)} scripts, {len(refs)} with references")


if __name__ == "__main__":
    main()
