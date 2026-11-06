#!/usr/bin/env python3
"""Gathers commands from public corpora for action_cases.py. Nothing here runs them.

Commands are not filtered by how dangerous they look, and attack recipes stay in. They are
reduced to what TrustAuto would really receive: one simple command as argv, without sudo,
redirections or shell syntax, the same way as build_dataset.py.

  python3 -I collect_commands.py --nl2bash ALL_CM --tldr PAGES_DIR --gtfobins BINS_DIR \
      --atomic INDEX_YAML --permission-corpus DIR --out COMMANDS_JSONL

Two groups are kept in the file with a reason but never run:
- opaque: the effect is in a file or argument the model cannot judge. These go to an approver.
- unobservable: aimed at the kernel, block devices or bootloader, which a container cannot show.
"""
import argparse
import collections
import csv
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import build_dataset as corpora  # noqa: E402

OPAQUE = re.compile(r"^(sh|ash|dash|bash|rbash|zsh|ksh|csh|tcsh|fish|busybox|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|php[0-9.]*|node|lua[0-9.]*|tclsh[0-9.]*|expect|gdb|make|cmake|ninja|gcc|cc|g\+\+|clang|docker|podman|ssh|scp|sftp|rsync|nc|ncat|socat|telnet)$")
UNOBSERVABLE = re.compile(r"^(mkfs(\..*)?|mke2fs|mkswap|fdisk|sfdisk|cfdisk|gdisk|sgdisk|parted|wipefs|blkdiscard|fstrim|badblocks|e2fsck|fsck(\..*)?|tune2fs|resize2fs|lvm|lv[a-z]+|vg[a-z]+|pv[a-z]+|mdadm|cryptsetup|losetup|mount|umount|swapon|swapoff|modprobe|insmod|rmmod|depmod|kexec|grub-[a-z-]+|update-grub|update-initramfs|mkinitramfs|dracut|efibootmgr|shutdown|halt|poweroff|reboot|init|telinit)$")
DEVICE_ARG = re.compile(r"(^|=)/dev/(?!null$|zero$|urandom$|random$|stdin$|stdout$|stderr$|tty$)")
KERNEL_ARG = re.compile(r"^(/proc/sys|/sys/|/proc/sysrq|kernel\.|vm\.)")


def held_back(argv):
    name = argv[0]
    if OPAQUE.match(name) or name.startswith("./") or name.endswith((".sh", ".py", ".pl", ".rb")):
        return "opaque"
    if UNOBSERVABLE.match(name) or any(DEVICE_ARG.search(a) or KERNEL_ARG.match(a) for a in argv[1:]):
        return "unobservable"
    return False


def from_permission_corpus(directory):
    """Only the command text is used. This corpus's labels mean something else than damage here."""
    for path in sorted(pathlib.Path(directory).rglob("*.csv")):
        with open(path, newline="", errors="replace") as handle:
            for row in csv.DictReader(handle):
                if (row.get("shell_family") or "").lower() in ("bash", "sh", "posix", "linux", "unix") or (row.get("platform") or "").lower() == "linux":
                    for argv in corpora.simple_commands(row.get("text") or ""):
                        yield argv


def main():
    parser = argparse.ArgumentParser()
    for name in ("nl2bash", "tldr", "gtfobins", "atomic", "permission-corpus", "out"):
        parser.add_argument("--" + name, required=True)
    options = parser.parse_args()
    sources = (("nl2bash", corpora.from_nl2bash(options.nl2bash)), ("tldr", corpora.from_tldr(options.tldr)),
               ("gtfobins", corpora.from_gtfobins(options.gtfobins)), ("atomic", corpora.from_atomic(options.atomic)),
               ("permission-corpus", from_permission_corpus(options.permission_corpus)))
    found = {}
    for source, commands in sources:
        for raw in commands:
            argv = corpora.clean_argv(raw)
            if argv:
                found.setdefault(tuple(argv), set()).add(source)
    with open(options.out, "w") as sink:
        for argv in sorted(found):
            sink.write(json.dumps({"argv": list(argv), "sources": sorted(found[argv]), "held_back": held_back(list(argv))}) + "\n")
    rows = [json.loads(line) for line in pathlib.Path(options.out).read_text().splitlines()]
    print(len(rows), "commands,", len({r["argv"][0] for r in rows}), "programs")
    print("by source", collections.Counter(s for r in rows for s in r["sources"]).most_common())
    print("held back", collections.Counter(r["held_back"] for r in rows).most_common())


if __name__ == "__main__":
    main()
