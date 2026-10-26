# Hidden-file cases (not for merging)

A failure injection in `example/passthrough.c` and two scripts, for the hidden-file fixes on
branch `hidden-files`. The injection is driven by marker files in the directory of the file
renamed; comments in `example/passthrough.c` list them.

    meson setup build -Dexamples=true && ninja -C build example/passthrough
    D=/tmp/hidden; mkdir -p $D/m $D/data
    build/example/passthrough $D/m
    python3 test/hidden-files/hidden.py $D/m$D/data $D/data                   # 25 cases
    SLOW_OPEN=1 python3 test/hidden-files/repro.py $D/m$D/data/r 10000 8 1    # commit 1
    fusermount3 -u $D/m

- `hidden.py MNT BACK [CASE...]` holds the target open in every case and checks both the mount
  (`MNT`) and the directory under it (`BACK`). It prints one `CASE <name>: PASS|FAIL` line per
  case and exits 1 if one failed.
- `repro.py` saves by rename while 8 readers open, read and close the target, and fails on any
  `ENOENT` or `EIO`.
- The data directory's path must not go through a symlink: example/passthrough returns an
  absolute symlink's target as it is, so the path would leave the mount.
