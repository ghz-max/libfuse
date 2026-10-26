#!/usr/bin/env python3
"""Hidden files of the high-level libfuse API (hard_remove off): a file unlinked or renamed over
while open is renamed to a hidden name and unlinked at its last release.

    hidden.py MNT BACK [CASE...]

MNT is a directory through the mount, BACK the same directory in the backend (bypassing the mount:
example/passthrough's real path). Each case runs in a subdirectory
of its own, where marker files turn on the failures that inject.diff adds to example/passthrough.
Prints "CASE <name>: PASS|FAIL <details>" per case; exit 1 if one failed.
Env: SRC_FAIL (default exdev): how stale_target_failed's rename fails (exdev, or gone).

Cases (the target is held open by another descriptor in each):
  names: a rename over the target and an rm both hide it as .fuse_hidden + 16 hex digits, in the
            backend; both are gone after the close
  failed: rename src.exdev over it fails (EXDEV): the target keeps its name and content
  renamed: a rename over it works; the held descriptor reads the old content; nothing is left
  unlinked: rm: the held descriptor reads it; nothing is left after the close
  lost: rename src.lost (renamed, then EIO): the rename is finished (ok); the target holds the moved
            file; nothing hidden left
  stuck: as failed, the target can not be renamed back: kept under its hidden name, not unlinked
  hide_reply_lost: the hide's rename happened but answered EIO (rename): EIO, the target keeps its
            name and content, before and after the close
  hide_reply_lost_rm: the same for an rm: EIO, the target is kept
  hide_fails: the hide's rename failed, not done: EIO, the target keeps its name
  hide_enoent: the hide's rename happened but answered ENOENT (a resent rename): EIO, the target
            keeps its name and content (not taken for a target already gone, and replaced unhidden)
  stale_target: the target was removed in the backend (another client): the rename over it works
  hidden_name_restored: after its hidden file was unlinked at the close, a file of that hidden name
            (restored from a trash) opens and reads; an O_PATH descriptor keeps the kernel's inode
            (and so libfuse's node) meanwhile, as a remember mount or a slow FORGET would
  name_taken: rename src.taken: another client takes the target's name while it is hidden, then
            EXDEV: the other client's file keeps the name, the target is kept under its hidden name
            (not unlinked at the close)
  name_taken_restore: rename src.exdev with race-create: another client creates the name just before
            the rename back: that file is not replaced; the target is kept under its hidden name
  stale_reader: a reader holds the target, the target is removed in the backend, then target.tmp is
            saved over it (rename): the rename works, the name reads the new file, the held
            descriptor's fstat and read reach the filesystem with a path (not EFAULT: a NULL path,
            which example/passthrough lstat()s), the mount is alive after the close, nothing left
  noreplace_name_taken: RENAME_NOREPLACE (renameat2, marker noreplace) over a held target removed in
            the backend, another client creating the name first (nr-race): EEXIST, the other
            client's file keeps the name, nothing hidden (before: hidden, then unlinked at the
            close)
  noreplace_stale: RENAME_NOREPLACE over a held target removed in the backend: works, and the held
            descriptor's fstat and read reach the filesystem with a path (not EFAULT)
  source_gone: rename src.gone: the source removed and the target's name taken by another client,
            then EIO: not taken for a rename that happened (another file): EIO, the other client's
            file keeps the name, the target is kept under its hidden name
  source_gone_same_ino: as source_gone, with every file answering the same inode number
            (same-ino) and the source of the other file's size, saved earlier: told apart by its
            modification time
  lost_same_ino: as lost, with same-ino: the rename is still finished
  hidden_name_race: another process takes the hidden name just before the hide's rename (hidrace,
            RENAME_NOREPLACE on: noreplace): its file survives, the rename works
  hidden_name_restored_locked: as hidden_name_restored, with a getattr of the pinned inode in flight
            (1 s, slow-getattr) while the close unlinks the hidden file: the restored file still
            opens and reads
  enosys: rename src.exdev where any rename flag answers ENOSYS (enosys): EXDEV, the target gets its
            name back (link and unlink), nothing hidden
  stale_target_failed: the target removed in the backend, then a rename over it that fails after the
            hide found it gone (src.exdev: EXDEV from inject.diff; with SRC_FAIL=gone the source is
            removed in the backend too: ENOENT), the held descriptor closed, another client creating
            the name: a new open of the name reads that file. A stale node moved aside before the
            rename, which then failed, would leave a filesystem's state for the open handle under
            the name with no release to drop it (only a filesystem that keeps state by path shows
            it)
  saves: saves by rename (write tmp, rename over) with a held reader, 50 times: every hidden name
            the backend shows is a hidden file's, none is left
"""
import ctypes
import errno
import os
import re
import sys
import threading
import time

MNT, BACK = sys.argv[1], sys.argv[2]
CASES = sys.argv[3:] or [
    'names', 'failed', 'renamed', 'unlinked', 'lost', 'stuck', 'hide_reply_lost',
    'hide_reply_lost_rm', 'hide_fails', 'hide_enoent', 'stale_target', 'hidden_name_restored',
    'name_taken', 'name_taken_restore', 'saves', 'stale_reader', 'noreplace_name_taken',
    'noreplace_stale', 'source_gone', 'hidden_name_race', 'hidden_name_restored_locked', 'enosys',
    'stale_target_failed', 'source_gone_same_ino', 'lost_same_ino'
]
REPLACED = LEFTOVER = '.fuse_hidden'
SRC_FAIL = os.environ.get('SRC_FAIL', 'exdev')
HIDDEN_RE = re.compile(r'^\.fuse_[a-z]+[0-9a-f]{16}$')
SETTLE = 0.5  # the release after a close is asynchronous


def ename(e):
    return errno.errorcode.get(e.errno, str(e.errno))


def put(p, b):
    with open(p, 'wb') as f:
        f.write(b)


def get(p):
    try:
        with open(p, 'rb') as f:
            return f.read().decode()
    except OSError as e:
        return ename(e)


class Case:
    def __init__(self, name):
        self.name = name
        self.m = os.path.join(MNT, name)    # through the mount
        self.b = os.path.join(BACK, name)   # in the backend
        os.makedirs(self.m, exist_ok=True)
        self.t = os.path.join(self.m, 'target')
        self.r = {}
        self.ok = True

    def hidden(self, where=None):
        d = self.b if where is None else where
        return sorted(n for n in os.listdir(d) if n.startswith('.fuse_'))

    def marker(self, name):
        put(os.path.join(self.b, name), b'')

    def check(self, what, cond):
        if not cond:
            self.ok = False
            self.r.setdefault('failed_checks', []).append(what)

    def rename(self, src, dst=None):
        try:
            os.rename(os.path.join(self.m, src), dst or self.t)
            return 'ok'
        except OSError as e:
            return ename(e)

    def held(self):
        return os.open(self.t, os.O_RDONLY)

    def leftover(self):
        """the hidden files' contents, and whether each has LEFTOVER's name"""
        h = self.hidden()
        return [get(os.path.join(self.b, n)) for n in h], all(n.startswith(LEFTOVER) for n in h)


RENAME_NOREPLACE = 1
_libc = ctypes.CDLL(None, use_errno=True)


def renameat2(src, dst, flags):
    AT_FDCWD = -100
    if _libc.renameat2(AT_FDCWD, src.encode(), AT_FDCWD, dst.encode(), flags) == 0:
        return 'ok'
    return errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))


def try_os(fn):
    """fn()'s result, or the errno name it raised"""
    try:
        return fn()
    except OSError as e:
        return ename(e)


def case_names(c):
    put(c.t, b'original')
    put(os.path.join(c.m, 'src'), b'new')
    fd = c.held()
    c.r['rename'] = c.rename('src')
    c.r['replaced'] = h = c.hidden()
    c.check('one replaced name', len(h) == 1 and HIDDEN_RE.match(h[0]) and h[0].startswith(REPLACED)
            and len(h[0]) == len(REPLACED) + 16)
    c.r['replaced_content'] = get(os.path.join(c.b, h[0])) if h else None
    os.close(fd)
    time.sleep(SETTLE)
    c.r['replaced_after_close'] = c.hidden()
    c.check('replaced gone', not c.r['replaced_after_close'])
    fd = c.held()
    os.unlink(c.t)
    c.r['unlinked'] = h = c.hidden()
    c.check('one .fuse_hidden name', len(h) == 1 and re.match(r'^\.fuse_hidden[0-9a-f]{16}$', h[0]))
    os.close(fd)
    time.sleep(SETTLE)
    c.r['unlinked_after_close'] = c.hidden()
    c.check('hidden gone', not c.r['unlinked_after_close'])


def case_failed(c):
    put(c.t, b'original')
    put(os.path.join(c.m, 'src.exdev'), b'new')
    fd = c.held()
    c.r['rename'] = c.rename('src.exdev')
    c.r['target'] = get(c.t)
    c.r['hidden'] = c.hidden()
    c.r['held'] = os.pread(fd, 100, 0).decode()
    os.close(fd)
    time.sleep(SETTLE)
    c.r['target_after_close'] = get(c.t)
    c.r['hidden_after_close'] = c.hidden()
    c.check('EXDEV', c.r['rename'] == 'EXDEV')
    c.check('target kept', c.r['target'] == 'original' and c.r['target_after_close'] == 'original')
    c.check('nothing hidden', not c.r['hidden'] and not c.r['hidden_after_close'])
    c.check('held reads', c.r['held'] == 'original')


def case_renamed(c):
    put(c.t, b'original')
    put(os.path.join(c.m, 'src'), b'new')
    fd = c.held()
    c.r['rename'] = c.rename('src')
    c.r['target'] = get(c.t)
    c.r['hidden'] = len(c.hidden())
    c.r['held'] = os.pread(fd, 100, 0).decode()
    os.close(fd)
    time.sleep(SETTLE)
    c.r['hidden_after_close'] = c.hidden()
    c.check('renamed', c.r['rename'] == 'ok' and c.r['target'] == 'new' and c.r['hidden'] == 1)
    c.check('held reads old', c.r['held'] == 'original')
    c.check('nothing left', not c.r['hidden_after_close'])


def case_unlinked(c):
    put(c.t, b'original')
    fd = c.held()
    os.unlink(c.t)
    c.r['exists'] = os.path.exists(c.t)
    c.r['held'] = os.pread(fd, 100, 0).decode()
    os.close(fd)
    time.sleep(SETTLE)
    c.r['left'] = sorted(os.listdir(c.b))
    c.check('unlinked', not c.r['exists'] and c.r['held'] == 'original' and not c.r['left'])


def case_lost(c):
    put(c.t, b'original')
    put(os.path.join(c.m, 'src.lost'), b'moved')
    fd = c.held()
    c.r['rename'] = c.rename('src.lost')
    c.r['target'] = get(c.t)
    c.r['held'] = os.pread(fd, 100, 0).decode()
    os.close(fd)
    time.sleep(SETTLE)
    c.r['target_after_close'] = get(c.t)
    c.r['left'] = sorted(os.listdir(c.b))
    c.check('rename finished', c.r['rename'] == 'ok')
    c.check('moved file kept', c.r['target'] == 'moved' and c.r['target_after_close'] == 'moved')
    c.check('held reads old', c.r['held'] == 'original')
    c.check('nothing left', c.r['left'] == ['target'])


def case_stuck(c):
    put(c.t, b'original')
    put(os.path.join(c.m, 'src.exdev'), b'new')
    c.marker('fail-restore')
    fd = c.held()
    c.r['rename'] = c.rename('src.exdev')
    c.r['hidden'] = [get(os.path.join(c.b, n)) for n in c.hidden()]
    os.close(fd)
    time.sleep(SETTLE)
    c.r['hidden_after_close'], named = c.leftover()
    c.r['leftover_names'] = c.hidden()
    c.check('EXDEV', c.r['rename'] == 'EXDEV')
    c.check('kept hidden', c.r['hidden'] == ['original'] and c.r['hidden_after_close'] == ['original'])
    c.check('leftover name', named)


def l5(c, op):
    put(c.t, b'original')
    put(os.path.join(c.m, 'src'), b'new')
    c.marker({'eio': 'hide-eio', 'enoent': 'hide-enoent'}.get(op, 'hide-lost'))
    fd = c.held()
    if op == 'rm':
        try:
            os.unlink(c.t)
            c.r['op'] = 'ok'
        except OSError as e:
            c.r['op'] = ename(e)
    else:
        c.r['op'] = c.rename('src')
    c.r['target'] = get(c.t)
    c.r['hidden'] = c.hidden()
    c.r['held'] = os.pread(fd, 100, 0).decode()
    os.close(fd)
    time.sleep(SETTLE)
    c.r['target_after_close'] = get(c.t)
    c.r['hidden_after_close'] = c.hidden()
    c.check('EIO', c.r['op'] == 'EIO')
    c.check('target kept', c.r['target'] == 'original' and c.r['target_after_close'] == 'original')
    c.check('nothing hidden', not c.r['hidden'] and not c.r['hidden_after_close'])
    c.check('held reads', c.r['held'] == 'original')


def case_hide_reply_lost(c):
    l5(c, 'rename')


def case_hide_reply_lost_rm(c):
    l5(c, 'rm')


def case_hide_fails(c):
    l5(c, 'eio')


def case_hide_enoent(c):
    l5(c, 'enoent')


def case_stale_target(c):
    put(c.t, b'original')
    put(os.path.join(c.m, 'src'), b'new')
    fd = c.held()
    os.unlink(os.path.join(c.b, 'target'))  # another client removed it
    c.r['rename'] = c.rename('src')
    c.r['target'] = get(c.t)
    try:  # informative: example/passthrough's getattr goes by path, gone (ENOENT, or EFAULT once unhashed)
        c.r['held'] = os.pread(fd, 100, 0).decode()
    except OSError as e:
        c.r['held'] = ename(e)
    os.close(fd)
    time.sleep(SETTLE)
    c.r['target_after_close'] = get(c.t)
    c.r['left'] = sorted(os.listdir(c.b))
    c.check('renamed', c.r['rename'] == 'ok' and c.r['target'] == 'new' and c.r['target_after_close'] == 'new')
    c.check('nothing left', c.r['left'] == ['target'])


def case_hidden_name_restored(c):
    put(c.t, b'original')
    pin = os.open(c.t, os.O_PATH)  # keeps the inode: no FORGET of the node
    fd = c.held()
    os.unlink(c.t)
    h = c.hidden()
    c.r['hidden'] = h
    os.close(fd)
    time.sleep(SETTLE)
    c.r['hidden_after_close'] = c.hidden()
    c.check('one hidden, unlinked at the close', len(h) == 1 and not c.r['hidden_after_close'])
    if len(h) == 1:
        put(os.path.join(c.b, h[0]), b'restored')  # restored from a trash, in the backend
        c.r['open_restored'] = get(os.path.join(c.m, h[0]))
        c.check('restored opens', c.r['open_restored'] == 'restored')
    os.close(pin)


def case_name_taken(c):
    put(c.t, b'original')
    put(os.path.join(c.m, 'src.taken'), b'new')
    fd = c.held()
    c.r['rename'] = c.rename('src.taken')
    c.r['target'] = get(c.t)
    c.r['held'] = os.pread(fd, 100, 0).decode()
    os.close(fd)
    time.sleep(SETTLE)
    c.r['target_after_close'] = get(c.t)
    c.r['hidden_after_close'], named = c.leftover()
    c.r['leftover_names'] = c.hidden()
    c.check('EXDEV', c.r['rename'] == 'EXDEV')
    c.check('other file kept', c.r['target'] == 'third\n' and c.r['target_after_close'] == 'third\n')
    c.check('target kept hidden', c.r['hidden_after_close'] == ['original'])
    c.check('leftover name', named)


def case_name_taken_restore(c):
    put(c.t, b'original')
    put(os.path.join(c.m, 'src.exdev'), b'new')
    c.marker('race-create')
    fd = c.held()
    c.r['rename'] = c.rename('src.exdev')
    c.r['target'] = get(c.t)
    os.close(fd)
    time.sleep(SETTLE)
    c.r['target_after_close'] = get(c.t)
    c.r['hidden_after_close'], named = c.leftover()
    c.r['leftover_names'] = c.hidden()
    c.check('EXDEV', c.r['rename'] == 'EXDEV')
    c.check('other file not replaced', c.r['target'] == 'third\n' and c.r['target_after_close'] == 'third\n')
    c.check('target kept hidden', c.r['hidden_after_close'] == ['original'])
    c.check('leftover name', named)


def case_saves(c):
    put(c.t, b'version 0')
    fd = c.held()  # a reader that keeps the first version
    seen = set()
    for i in range(1, 51):
        tmp = os.path.join(c.m, 'target.tmp')
        put(tmp, b'version %d' % i)
        os.rename(tmp, c.t)
        seen.update(c.hidden())
    c.r['held'] = os.pread(fd, 100, 0).decode()
    os.close(fd)
    time.sleep(SETTLE)
    c.r['hidden_seen'] = sorted(seen)
    c.r['left'] = sorted(os.listdir(c.b))
    c.check('held reads version 0', c.r['held'] == 'version 0')
    c.check('only replaced names', seen and all(n.startswith(REPLACED) and HIDDEN_RE.match(n) for n in seen))
    c.check('nothing left', c.r['left'] == ['target'])


def stale_held(c):
    """the held descriptor of a target removed in the backend: its fstat and its read"""
    fd = c.r.pop('_fd')
    c.r['held_fstat'] = try_os(lambda: 'ok' if os.fstat(fd) else 'ok')
    c.r['held_read'] = try_os(lambda: os.pread(fd, 100, 0).decode())
    c.r['held_close'] = try_os(lambda: os.close(fd) or 'ok')
    c.check('held fstat not a NULL path', c.r['held_fstat'] != 'EFAULT')
    c.check('held read not a NULL path', c.r['held_read'] != 'EFAULT')


def case_stale_reader(c):
    put(c.t, b'original')
    c.r['_fd'] = c.held()
    os.unlink(os.path.join(c.b, 'target'))  # another client removed it
    put(os.path.join(c.m, 'target.tmp'), b'new')
    c.r['rename'] = c.rename('target.tmp')
    c.r['target'] = get(c.t)
    stale_held(c)
    time.sleep(SETTLE)
    c.r['alive'] = try_os(lambda: sorted(os.listdir(c.m)))
    c.r['target_after_close'] = get(c.t)
    c.r['left'] = try_os(lambda: sorted(os.listdir(c.b)))
    c.check('renamed', c.r['rename'] == 'ok' and c.r['target'] == 'new' and c.r['target_after_close'] == 'new')
    c.check('mount alive', isinstance(c.r['alive'], list))
    c.check('nothing left', c.r['left'] == ['target'])


def case_noreplace_name_taken(c):
    put(c.t, b'original')
    put(os.path.join(c.m, 'src'), b'new')
    c.marker('noreplace')
    c.marker('nr-race')
    fd = c.held()
    os.unlink(os.path.join(c.b, 'target'))  # removed by another client, who creates it again (nr-race)
    c.r['rename'] = renameat2(os.path.join(c.m, 'src'), c.t, RENAME_NOREPLACE)
    c.r['target'] = get(c.t)
    c.r['hidden'] = c.hidden()
    try_os(lambda: os.close(fd))
    time.sleep(SETTLE)
    c.r['target_after_close'] = get(c.t)
    c.r['hidden_after_close'] = c.hidden()
    c.check('EEXIST', c.r['rename'] == 'EEXIST')
    c.check('other file kept', c.r['target'] == 'third\n' and c.r['target_after_close'] == 'third\n')
    c.check('nothing hidden', not c.r['hidden'] and not c.r['hidden_after_close'])


def case_noreplace_stale(c):
    put(c.t, b'original')
    put(os.path.join(c.m, 'src'), b'new')
    c.marker('noreplace')
    c.r['_fd'] = c.held()
    os.unlink(os.path.join(c.b, 'target'))  # another client removed it
    c.r['rename'] = renameat2(os.path.join(c.m, 'src'), c.t, RENAME_NOREPLACE)
    c.r['target'] = get(c.t)
    stale_held(c)
    time.sleep(SETTLE)
    c.r['target_after_close'] = get(c.t)
    c.r['hidden_after_close'] = c.hidden()
    c.check('renamed', c.r['rename'] == 'ok' and c.r['target'] == 'new' and c.r['target_after_close'] == 'new')
    c.check('nothing hidden', not c.r['hidden_after_close'])


def case_source_gone(c):
    put(c.t, b'original')
    put(os.path.join(c.m, 'src.gone'), b'new')
    fd = c.held()
    c.r['rename'] = c.rename('src.gone')
    c.r['target'] = get(c.t)
    c.r['held'] = os.pread(fd, 100, 0).decode()
    os.close(fd)
    time.sleep(SETTLE)
    c.r['target_after_close'] = get(c.t)
    c.r['hidden_after_close'], named = c.leftover()
    c.r['leftover_names'] = c.hidden()
    c.check('EIO', c.r['rename'] == 'EIO')
    c.check('other file kept', c.r['target'] == 'third\n' and c.r['target_after_close'] == 'third\n')
    c.check('target kept hidden', c.r['hidden_after_close'] == ['original'])
    c.check('leftover name', named)


def case_source_gone_same_ino(c):
    """source_gone where the other client's file has the source's inode number and size"""
    c.marker('same-ino')
    put(c.t, b'original')
    src = os.path.join(c.m, 'src.gone')
    put(src, b'other\n')  # the size of the file the injection creates ('third\n')
    os.utime(src, (1e9, 1e9))  # saved earlier: its modification time tells it apart
    fd = c.held()
    c.r['rename'] = c.rename('src.gone')
    c.r['target'] = get(c.t)
    os.close(fd)
    time.sleep(SETTLE)
    c.r['target_after_close'] = get(c.t)
    c.r['hidden_after_close'], named = c.leftover()
    c.check('EIO', c.r['rename'] == 'EIO')
    c.check('other file kept', c.r['target'] == 'third\n' and c.r['target_after_close'] == 'third\n')
    c.check('target kept hidden', c.r['hidden_after_close'] == ['original'])
    c.check('leftover name', named)


def case_lost_same_ino(c):
    """lost where every file has the same inode number: the moved file is still recognized"""
    c.marker('same-ino')
    put(c.t, b'original')
    put(os.path.join(c.m, 'src.lost'), b'moved')
    fd = c.held()
    c.r['rename'] = c.rename('src.lost')
    c.r['target'] = get(c.t)
    os.close(fd)
    time.sleep(SETTLE)
    c.r['left'] = sorted(n for n in os.listdir(c.b) if n != 'same-ino')
    c.check('rename finished', c.r['rename'] == 'ok')
    c.check('moved file kept', c.r['target'] == 'moved')
    c.check('nothing left', c.r['left'] == ['target'])


def case_stale_target_failed(c):
    put(c.t, b'original')
    put(os.path.join(c.m, 'src.exdev'), b'new')
    fd = c.held()
    os.unlink(os.path.join(c.b, 'target'))  # another client removed it
    if SRC_FAIL == 'gone':  # and the source: the filesystem's rename answers ENOENT
        os.unlink(os.path.join(c.b, 'src.exdev'))
    c.r['rename'] = c.rename('src.exdev')
    c.r['hidden'] = c.hidden()
    c.r['held_close'] = try_os(lambda: os.close(fd) or 'ok')
    time.sleep(SETTLE)
    put(os.path.join(c.b, 'target'), b'third\n')  # another client creates the name
    time.sleep(1.2)  # past a 1 s entry timeout: the open below looks the name up
    c.r['target'] = get(c.t)
    c.r['left'] = sorted(os.listdir(c.b))
    c.check('rename failed', c.r['rename'] == ('ENOENT' if SRC_FAIL == 'gone' else 'EXDEV'))
    c.check('the new file reads its own content', c.r['target'] == 'third\n')
    c.check('nothing hidden', not c.r['hidden'])
    c.check('nothing left', c.r['left'] == (['target'] if SRC_FAIL == 'gone' else ['src.exdev', 'target']))


def case_hidden_name_race(c):
    put(c.t, b'original')
    put(os.path.join(c.m, 'src'), b'new')
    c.marker('noreplace')
    c.marker('hidrace')
    fd = c.held()
    c.r['rename'] = c.rename('src')
    c.r['target'] = get(c.t)
    c.r['held'] = os.pread(fd, 100, 0).decode()
    os.close(fd)
    time.sleep(SETTLE)
    c.r['hidden_after_close'] = [get(os.path.join(c.b, n)) for n in c.hidden()]
    c.check('renamed', c.r['rename'] == 'ok' and c.r['target'] == 'new')
    c.check('held reads old', c.r['held'] == 'original')
    c.check("the other process's file kept", c.r['hidden_after_close'] == ['third\n'])


def case_hidden_name_restored_locked(c):
    put(c.t, b'original')
    pin = os.open(c.t, os.O_PATH)  # keeps the inode: no FORGET of the node
    fd = c.held()
    os.unlink(c.t)
    h = c.hidden()
    c.r['hidden'] = h
    c.marker('slow-getattr')  # after the hide: its hidden_name() getattrs would wait too
    st = {}

    def slow_fstat():
        t0 = time.monotonic()
        st['r'] = try_os(lambda: os.fstat(pin) and 'ok')
        st['s'] = round(time.monotonic() - t0, 2)
    th = threading.Thread(target=slow_fstat)
    th.start()
    time.sleep(0.3)  # the getattr is in flight: its path lock holds the node
    os.close(fd)
    th.join()
    os.unlink(os.path.join(c.b, 'slow-getattr'))
    time.sleep(SETTLE)
    c.r['getattr'] = st.get('r')
    c.r['getattr_s'] = st.get('s')  # about 1 s: the getattr was in flight during the close
    c.r['hidden_after_close'] = c.hidden()
    c.check('one hidden, unlinked at the close', len(h) == 1 and not c.r['hidden_after_close'])
    if len(h) == 1:
        put(os.path.join(c.b, h[0]), b'restored')  # restored from a trash, in the backend
        c.r['open_restored'] = get(os.path.join(c.m, h[0]))
        c.check('restored opens', c.r['open_restored'] == 'restored')
    os.close(pin)


def case_enosys(c):
    put(c.t, b'original')
    put(os.path.join(c.m, 'src.exdev'), b'new')
    c.marker('enosys')
    fd = c.held()
    c.r['rename'] = c.rename('src.exdev')
    c.r['target'] = get(c.t)
    c.r['hidden'] = c.hidden()
    os.close(fd)
    time.sleep(SETTLE)
    c.r['target_after_close'] = get(c.t)
    c.r['hidden_after_close'] = c.hidden()
    c.check('EXDEV', c.r['rename'] == 'EXDEV')
    c.check('target back', c.r['target'] == 'original' and c.r['target_after_close'] == 'original')
    c.check('nothing hidden', not c.r['hidden'] and not c.r['hidden_after_close'])


failed = 0
for name in CASES:
    c = Case(name)
    try:
        globals()['case_' + name](c)
    except Exception as e:  # noqa: BLE001 - a crash is a failed case
        c.ok = False
        c.r['exception'] = repr(e)
    if '_fd' in c.r:
        try_os(lambda: os.close(c.r.pop('_fd')))
    if not c.ok:
        failed += 1
    print(f"CASE {name}: {'PASS' if c.ok else 'FAIL'} {c.r}", flush=True)
sys.exit(1 if failed else 0)
