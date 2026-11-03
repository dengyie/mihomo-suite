"""Advisory lock around live Clash config writes — serialised across NFS hosts.

Four writers read-modify-write ``config.yaml`` / ``config.mac-merged.yaml``:
``apply-local-import.py`` (keeper), ``subscription-manager.py`` (gateway),
``rules-reconciler.py`` and ``hutao-bridge-guard.py``. The gateway runs on both
Beam hosts and its admin endpoints reach the same reconcile path, while the
shared ``/personal`` mount is NFSv3 ``nolock,local_lock=all`` — ``flock`` there
is enforced by the *local* kernel only, so it serialises writers on one host but
cannot see a writer running in another host's kernel.

The lock therefore layers two mechanisms:

``fcntl.flock``
    Cheap, reentrant per open-file-description, and released by the kernel even
    on ``SIGKILL``. Kept as the fast path and the intra-host gate.

``mkdir`` lock directory
    ``mkdir`` is a single atomic RPC executed on the NFS server, so it excludes
    writers across hosts regardless of the ``nolock`` mount option (this is the
    classic NFS-safe locking primitive). The directory holds an owner token
    (host, pid, wall clock) so a holder that died without releasing can be
    reclaimed: a same-host holder is checked with ``kill(pid, 0)``, while a
    foreign holder (whose pid we cannot inspect) is reclaimed once its token has
    been observed unchanged for ``STALE_AFTER`` seconds — measured on our own
    monotonic clock, so host clock skew cannot mask a stale lock.

Critical sections are milliseconds (parse + render + ``os.replace``), so the
stale window is orders of magnitude larger than any legitimate hold.
"""
from __future__ import annotations

import errno
import fcntl
import os
import random
import socket
import threading
import time
from pathlib import Path

LOCK_RELATIVE = Path('subscriptions') / '.subscription.lock'

# A foreign holder is presumed dead once its token has not changed for this
# long. Writes take milliseconds; this only has to beat a crash, not a slow NFS
# round trip.
STALE_AFTER = float(os.environ.get('CLASH_LOCK_STALE_AFTER', '15'))
# Give up rather than block a request forever. Must exceed STALE_AFTER so a
# crashed foreign holder can still be reclaimed within one acquisition.
ACQUIRE_TIMEOUT = float(os.environ.get('CLASH_LOCK_TIMEOUT', '30'))
# Grace before treating a lock dir with no readable token as abandoned (covers
# the instant between mkdir and the token write).
MISSING_TOKEN_GRACE = float(os.environ.get('CLASH_LOCK_MISSING_GRACE', '5'))

_POLL_MIN = 0.02
_POLL_MAX = 0.25

_registry_guard = threading.Lock()
_rlocks: dict[str, threading.RLock] = {}
_depths: dict[str, int] = {}
_fds: dict[str, object] = {}


def default_lock_path() -> Path:
    root = Path(os.environ.get('CLASH_ROOT', '/personal/clash')).resolve()
    return root / LOCK_RELATIVE


def _host_id() -> str:
    """Stable host identity for the owner token.

    ``CLASH_LOCK_HOST_ID`` is an explicit override for tests, and for hosts whose
    hostname does not distinguish them (both Beam containers share a
    ``bohrium-*`` prefix, so the gateway already keys log paths off the IP).
    """
    override = (os.environ.get('CLASH_LOCK_HOST_ID') or '').strip()
    if override:
        return override
    try:
        return socket.gethostname() or 'unknown'
    except OSError:
        return 'unknown'


def _parse_token(raw: str):
    try:
        host, pid, ts = raw.strip().split('|', 2)
        return host, int(pid), float(ts)
    except (AttributeError, ValueError):
        return None


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, owned by someone else
    except OSError:
        return False
    return True


def _read_token(lock_dir: Path) -> str:
    try:
        return (lock_dir / 'owner').read_text(encoding='utf-8', errors='replace')
    except OSError:
        return ''


def _write_token(lock_dir: Path, body: str) -> None:
    token = lock_dir / 'owner'
    tmp = lock_dir / f'owner.tmp-{os.getpid()}-{random.randrange(1 << 20)}'
    with open(tmp, 'w', encoding='utf-8') as fh:
        fh.write(body)
    try:
        os.chmod(tmp, 0o664)
    except OSError:
        pass
    os.replace(tmp, token)


def _reclaim(lock_dir: Path) -> bool:
    """Atomically steal and remove a stale lock dir.

    ``rename`` succeeds for exactly one stealer, so two hosts reclaiming the same
    stale lock cannot both end up owning it. Returns True if this call removed it.
    """
    victim = lock_dir.with_name(
        f'{lock_dir.name}.stale.{os.getpid()}.{random.randrange(1 << 20)}'
    )
    try:
        os.rename(lock_dir, victim)
    except OSError as exc:
        if exc.errno in (errno.ENOENT, errno.ENOTDIR):
            return False  # someone else reclaimed it first
        raise
    try:
        (victim / 'owner').unlink()
    except OSError:
        pass
    try:
        os.rmdir(victim)
    except OSError:
        pass
    return True


def _acquire_dir_lock(lock_dir: Path, timeout: float | None = None) -> None:
    timeout = ACQUIRE_TIMEOUT if timeout is None else timeout
    deadline = time.monotonic() + timeout
    poll = _POLL_MIN
    body = f'{_host_id()}|{os.getpid()}|{time.time():.3f}\n'

    seen_raw: str | None = None
    seen_since = 0.0

    while True:
        try:
            os.mkdir(lock_dir, 0o775)
        except FileExistsError:
            pass
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
        else:
            try:
                _write_token(lock_dir, body)
            except BaseException:
                try:
                    os.rmdir(lock_dir)
                except OSError:
                    pass
                raise
            return

        now = time.monotonic()
        raw = _read_token(lock_dir)
        if raw != seen_raw:
            seen_raw, seen_since = raw, now
        observed = now - seen_since

        parsed = _parse_token(raw)
        stale = False
        if parsed is None:
            # mkdir landed but the holder died before writing its token.
            stale = observed >= MISSING_TOKEN_GRACE
        else:
            host, pid, _ts = parsed
            if host == _host_id():
                # Same kernel: exact liveness, no need to wait out the lease.
                stale = not _pid_alive(pid)
            else:
                # Foreign kernel: judge by how long we have watched this token,
                # which uses only our own clock (immune to host clock skew).
                stale = observed >= STALE_AFTER

        if stale and _reclaim(lock_dir):
            continue

        if now >= deadline:
            raise TimeoutError(
                f'timed out after {timeout:.0f}s waiting for the cross-host '
                f'config lock {lock_dir} (holder token: {raw.strip() or "none"})'
            )
        time.sleep(poll + random.uniform(0, poll))
        poll = min(poll * 2, _POLL_MAX)


def _release_dir_lock(lock_dir: Path) -> None:
    parsed = _parse_token(_read_token(lock_dir))
    # Only remove the dir if it is still ours: a stale reclaim may have renamed
    # it away from under us while we were writing.
    if parsed is None or parsed[0] != _host_id() or parsed[1] != os.getpid():
        return
    try:
        (lock_dir / 'owner').unlink()
    except OSError:
        pass
    try:
        os.rmdir(lock_dir)
    except OSError:
        pass


class ClashConfigLock:
    """Reentrant, cross-process *and* cross-host exclusive lock for one config."""

    def __init__(self, lock_file: Path | str | None = None):
        self.path = str(Path(lock_file).resolve()) if lock_file else str(default_lock_path())
        self.dir_path = Path(self.path + '.d')
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
                try:
                    fcntl.flock(fd.fileno(), fcntl.LOCK_EX)
                except BaseException:
                    fd.close()
                    raise
                with _registry_guard:
                    _fds[self.path] = fd
                try:
                    _acquire_dir_lock(self.dir_path)
                except BaseException:
                    with _registry_guard:
                        _fds.pop(self.path, None)
                    try:
                        fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
                    finally:
                        fd.close()
                    raise
            except BaseException:
                with _registry_guard:
                    _depths.pop(self.path, None)
                self._rlock.release()
                raise
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        try:
            fd = None
            release_dir = False
            with _registry_guard:
                depth = _depths.get(self.path, 0)
                if depth <= 1:
                    _depths.pop(self.path, None)
                    fd = _fds.pop(self.path, None)
                    release_dir = True
                else:
                    _depths[self.path] = depth - 1
            if release_dir:
                _release_dir_lock(self.dir_path)
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
