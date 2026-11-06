#!/usr/bin/env python3
"""Runs a command on a real pseudo-terminal and answers prompts, for the
integration test. A prompt is matched as a substring of recent output.

  pty_driver.py [--expect TEXT --send TEXT]... -- COMMAND [ARG...]

Answers can be given as env:NAME so passwords stay out of the process list.
Prints everything the command wrote and exits with its exit status.
"""
import os
import pty
import select
import sys
import time

TIMEOUT_SECONDS = 60


def parse(argv):
    steps = []
    i = 0
    while i < len(argv) and argv[i] != "--":
        if argv[i] != "--expect" or argv[i + 2] != "--send":
            sys.exit("usage: pty_driver.py [--expect TEXT --send TEXT]... -- COMMAND")
        answer = argv[i + 3]
        if answer.startswith("env:"):
            answer = os.environ[answer[4:]]
        steps.append((argv[i + 1].encode(), answer.encode()))
        i += 4
    return steps, argv[i + 1 :]


def main():
    steps, command = parse(sys.argv[1:])
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(command[0], command)

    seen = b""
    unmatched = b""
    deadline = time.monotonic() + TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 1.0)
        if not ready:
            continue
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        seen += chunk
        unmatched += chunk
        if steps and steps[0][0] in unmatched:
            _, answer = steps.pop(0)
            unmatched = b""
            os.write(fd, answer + b"\n")
    else:
        os.kill(pid, 9)
        sys.stdout.write("pty_driver: timed out\n")

    _, status = os.waitpid(pid, 0)
    sys.stdout.write(seen.decode(errors="replace"))
    sys.exit(os.waitstatus_to_exitcode(status) & 0xFF)


if __name__ == "__main__":
    main()
