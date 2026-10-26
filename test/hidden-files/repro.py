#!/usr/bin/env python3
"""Save by rename against readers that open and close the target, on a high-level libfuse mount
(example/passthrough, hard_remove off). SLOW_OPEN=1 creates DIR/slow-open (the injection in
example/passthrough.c: a 1 ms sleep in open()), and any .fuse_ name left is reported.

    repro.py DIR [SAVES] [READERS] [HOLD_MS]

The saver writes DIR/target.tmp and renames it over DIR/target, SAVES times (default 2000).
READERS threads (default 4) open DIR/target, read it, keep it open HOLD_MS (default 1) and close
it, until the saves are done: the target is then mostly open when it is renamed over, so libfuse
hides it (.fuse_hidden) and unlinks it at the release of its last open.
Exit 1 if a reader's open or read failed: with libfuse counting an open only after the
filesystem's open, the release of a replaced (hidden) target's last other handle unlinks its
.fuse_hidden file under an open in flight, which then fails with ENOENT.
"""
import errno
import json
import os
import sys
import threading
import time

d = sys.argv[1]
saves = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
readers = int(sys.argv[3]) if len(sys.argv) > 3 else 4
hold = float(sys.argv[4]) / 1000 if len(sys.argv) > 4 else 0.001
os.makedirs(d, exist_ok=True)
if os.environ.get("SLOW_OPEN"):
    # inject.diff's passthrough sleeps 1 ms in open() with this file in the directory
    open(os.path.join(d, "slow-open"), "w").close()
target = os.path.join(d, "target")
tmp = os.path.join(d, "target.tmp")


def save(i):
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        os.write(fd, b"version %d\n" % i)
    finally:
        os.close(fd)
    os.rename(tmp, target)


save(0)
done = threading.Event()
lock = threading.Lock()
errors = {}
reads = 0


def failed(where, e):
    with lock:
        key = where + " " + errno.errorcode.get(e.errno, str(e.errno))
        errors[key] = errors.get(key, 0) + 1


def reader():
    global reads
    while not done.is_set():
        try:
            fd = os.open(target, os.O_RDONLY)
        except OSError as e:
            failed("open", e)
            continue
        try:
            os.read(fd, 4096)
            with lock:
                reads += 1
            time.sleep(hold)
        except OSError as e:
            failed("read", e)
        finally:
            os.close(fd)


threads = [threading.Thread(target=reader) for _ in range(readers)]
for t in threads:
    t.start()
for i in range(1, saves + 1):
    save(i)
done.set()
for t in threads:
    t.join()
left = sorted(n for n in os.listdir(d) if n.startswith(".fuse_"))
print(json.dumps({"saves": saves, "reads": reads, "errors": errors, "fuse_hidden_left": left}))
sys.exit(1 if errors else 0)
