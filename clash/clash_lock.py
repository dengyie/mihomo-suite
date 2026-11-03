"""Reentrant advisory lock around live Clash config writes.

Both the keeper (``apply-local-import.py``) and the gateway process
(``subscription-manager.py``) read-modify-write ``config.yaml`` /
``config.mac-merged.yaml``. ``fcntl.flock`` is per open-file-description, so two
fds from *different processes* contend as intended, while two fds from the *same*
process would deadlock each other. This wrapper keeps one fd per lock path per
process plus a reentrant in-process mutex, so nested acquisition (e.g. an admin
action that already holds the lock calling ``reconcile_target_config``) is a
no-op while cross-process writers still serialize on the flock.

Scope caveat: the lock file lives on the shared ``/personal`` NFS mount, which is
mounted with ``nolock,local_lock=all``. ``flock`` is therefore enforced only by
the local kernel: it serializes writers on the *same* host, but a writer in
another host's kernel (e.g. pxed's gateway writing the same config) is not
blocked. The lock removes the intra-host interleaving; cross-host last-writer
wins remains possible and is handled by atomic replacement rather than locking.
"""
from __future__ import annotations

import fcntl
import os
import threading
from pathlib import Path

LOCK_RELATIVE = Path('subscriptions') / '.subscription.lock'

_registry_guard = threading.Lock()
_rlocks: dict[str, threading.RLock] = {}
_depths: dict[str, int] = {}
_fds: dict[str, object] = {}


def default_lock_path() -> Path:
    root = Path(os.environ.get('CLASH_ROOT', '/personal/clash')).resolve()
    return root / LOCK_RELATIVE


class ClashConfigLock:
    """Reentrant, cross-process exclusive lock for one config lock file."""

    def __init__(self, lock_file: Path | str | None = None):
        self.path = str(Path(lock_file).resolve()) if lock_file else str(default_lock_path())
        with _registry_guard:
            rlock = _rlocks.get(self.path)
            if rlock is None:
                rlock = threading.RLock()
                _rlocks[self.path] = rlock
        self._rlock = rlock

    def __enter__(self) -> 'ClashConfigLock':
        self._rlock.acquire()
        with _registry_guard:
            depth = _depths.get(self.path, 0) + 1
            _depths[self.path] = depth
            first = depth == 1
        if first:
            try:
                Path(self.path).parent.mkdir(parents=True, exist_ok=True)
                fd = open(self.path, 'a+')
                fcntl.flock(fd.fileno(), fcntl.LOCK_EX)
            except BaseException:
                with _registry_guard:
                    _depths.pop(self.path, None)
                self._rlock.release()
                raise
            with _registry_guard:
                _fds[self.path] = fd
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        try:
            fd = None
            with _registry_guard:
                depth = _depths.get(self.path, 0)
                if depth <= 1:
                    _depths.pop(self.path, None)
                    fd = _fds.pop(self.path, None)
                else:
                    _depths[self.path] = depth - 1
            if fd is not None:
                try:
                    fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
                finally:
                    fd.close()
        finally:
            self._rlock.release()
        return False


def atomic_write_text(target: Path, content: str) -> None:
    """Replace *target* atomically, preserving its mode and ownership.

    ``Path.write_text`` truncates before writing, so a reader in another host's
    kernel (the shared NFS mount is ``nolock``) — or the process dying mid-write
    — can observe a partial YAML document. ``os.replace`` within the same
    directory is atomic; the temp file inherits the live file's mode and owner so
    the gateway user keeps write access.
    """
    try:
        st = target.stat()
    except OSError:
        st = None
    tmp = target.with_name(f'.{target.name}.tmp-{os.getpid()}')
    try:
        with open(tmp, 'w', encoding='utf-8') as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        if st is not None:
            try:
                os.chmod(tmp, st.st_mode & 0o7777)
            except OSError:
                pass
            try:
                os.chown(tmp, st.st_uid, st.st_gid)
            except OSError:
                pass
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
