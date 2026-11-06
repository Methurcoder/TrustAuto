#!/usr/bin/env python3
# Drives a real shell on a PTY as an unprivileged demo user and records its bytes with times.
# usage (as root, TrustAuto installed): record.py OUT.jsonl USER
import json, os, pty, select, sys, time

out, user = sys.argv[1:3]
RC = f"/home/{user}/.demorc"
ENV = {"TERM": "xterm-256color", "PAGER": "cat", "LANG": "C.UTF-8", "COLUMNS": "78", "LINES": "24", "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "HOME": f"/home/{user}"}
pid, fd = pty.fork()
if pid == 0:
    os.execve("/usr/sbin/runuser", ["runuser", "-u", user, "--", "/bin/bash", "--noprofile", "--rcfile", RC, "-i"], ENV)
import fcntl, struct, termios
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 78, 0, 0))
log, start = [], time.time()

def read_until(done, timeout):
    buf, end = b"", time.time() + timeout
    while time.time() < end:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if ready:
            try:
                data = os.read(fd, 65536)
            except OSError:
                break
            if not data:
                break
            log.append({"t": round(time.time() - start, 3), "data": data.decode("utf-8", "replace")})
            buf += data
            if done(buf):
                return buf
    return buf

PROMPT = b"$ "
def at_prompt(buf):
    return buf.endswith(PROMPT)

read_until(at_prompt, 10)

def command(text, timeout=120, stop_on=None, then=None):
    log.append({"t": round(time.time() - start, 3), "command": text})
    os.write(fd, text.encode() + b"\n")
    if stop_on:
        buf = read_until(lambda b: stop_on in b, timeout)
        if then:
            time.sleep(0.5)
            os.write(fd, then)
    return read_until(at_prompt, timeout)

def must_be_refused(text):
    said = command(text)
    if b"deny" not in said:
        sys.exit(f"not refused, stopping before anything runs: {said!r}")

# A dangerous command is typed only after explain says it is refused.
must_be_refused("trustauto explain -- mkfs -t ext4 /dev/sda")
log.append({"t": round(time.time() - start, 3), "mark": "start"})
command("apt update", 180)
command("apt search '^vim$'")
command("trustauto explain -- apt install htop")
command("apt install ./evil.deb", 30, stop_on=b"assword", then=b"\x04")
command("trustauto explain -- rm -rf /")
command("trustauto run -- mkfs -t ext4 /dev/sda")
command("id -u")
command("trustauto off")
command("trustauto on")
os.write(fd, b"exit\n")
read_until(lambda b: False, 1)
open(out, "w").write("".join(json.dumps(r) + "\n" for r in log))
