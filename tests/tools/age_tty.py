"""Runs a shell command under a pseudo-terminal and types a passphrase at every age prompt (age reads /dev/tty).
Usage: python3 tests/tools/age_tty.py '<passphrase>' '<shell command>'   (synthetic test passphrases only).
Exit status = the command's; its terminal output (prompts, no passphrase echo) goes to stderr, its stdout is untouched."""
import os
import pty
import re
import select
import sys
import time

passphrase, command = sys.argv[1], sys.argv[2]
pid, fd = pty.fork()
if pid == 0:
    os.execvp('/bin/sh', ['/bin/sh', '-c', command])
seen, deadline = b'', time.time() + 90
while time.time() < deadline:
    ready, _, _ = select.select([fd], [], [], 0.3)
    if not ready:
        continue
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        break
    if not chunk:
        break
    seen += chunk
    if re.search(rb'passphrase[^\n]*:\s*(\x1b\[[0-9;]*[A-Za-z])*\s*$', chunk, re.I) or chunk.rstrip().endswith(b'one):'):
        os.write(fd, passphrase.encode() + b'\n')
_, status = os.waitpid(pid, 0)
sys.stderr.write(seen.decode('utf-8', 'replace'))
sys.exit(os.waitstatus_to_exitcode(status))
