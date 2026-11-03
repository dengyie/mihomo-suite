"""Tests for clash/clash_lock.py — the cross-host config write lock.

The production ``/personal`` mount is NFSv3 ``nolock,local_lock=all``, so
``fcntl.flock`` only serialises writers in the same kernel. The lock therefore
adds an NFS-atomic ``mkdir`` directory on top. These tests pin that behaviour:

* mutual exclusion across *different host ids* (the mkdir layer, not flock),
* a stale foreign holder is reclaimed after the observation window,
* a fresh foreign holder is never stolen from (it just times out),
* a dead same-host holder is reclaimed immediately,
* a lock dir left without a token is reclaimed after the grace period,
* reentrancy and the mode-preserving atomic write still hold.
"""

import importlib.util
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CLASH_DIR = ROOT / "clash"


def _load():
    sys.path.insert(0, str(CLASH_DIR))
    spec = importlib.util.spec_from_file_location("clash_lock_under_test", CLASH_DIR / "clash_lock.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cl = _load()


@pytest.fixture(autouse=True)
def _clean_registry():
    """Each test starts with empty per-process lock state."""
    cl._rlocks.clear()
    cl._depths.clear()
    cl._fds.clear()
    yield
    cl._rlocks.clear()
    cl._depths.clear()
    cl._fds.clear()


@pytest.fixture()
def lock_path(tmp_path):
    return tmp_path / "subscriptions" / ".subscription.lock"


def _holder(token_dir: Path, host: str, pid: int, age: float = 0.0) -> Path:
    """Fabricate a lock dir owned by ``host``/``pid``."""
    token_dir.mkdir(parents=True)
    (token_dir / "owner").write_text(f"{host}|{pid}|{time.time() - age:.3f}\n", encoding="utf-8")
    return token_dir


# --------------------------------------------------------------------------
# basic lifecycle
# --------------------------------------------------------------------------

def test_acquire_creates_and_releases_lock(lock_path):
    with cl.ClashConfigLock(lock_path):
        assert lock_path.exists()          # flock file
        assert (lock_path.parent / (lock_path.name + ".d")).is_dir()
        assert (lock_path.parent / (lock_path.name + ".d") / "owner").exists()
    assert not (lock_path.parent / (lock_path.name + ".d")).exists()
    # no temp token residue
    assert not list(lock_path.parent.glob("*.tmp-*"))


def test_reentrant_acquisition_does_not_deadlock(lock_path, monkeypatch):
    monkeypatch.setattr(cl, "STALE_AFTER", 0.01)
    with cl.ClashConfigLock(lock_path):
        with cl.ClashConfigLock(lock_path):
            with cl.ClashConfigLock(lock_path):
                pass
    assert not (lock_path.parent / (lock_path.name + ".d")).exists()


# --------------------------------------------------------------------------
# cross-host exclusion (the point of the change)
# --------------------------------------------------------------------------

_SUBPROC = textwrap.dedent(
    """
    import importlib.util, os, sys, time
    spec = importlib.util.spec_from_file_location("cl", sys.argv[1])
    cl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cl)
    lock_path, host, marker, hold = sys.argv[2], sys.argv[3], sys.argv[4], float(sys.argv[5])
    os.environ["CLASH_LOCK_HOST_ID"] = host
    with cl.ClashConfigLock(lock_path):
        # stamp only after the lock is actually held
        with open(marker, "a") as fh:
            fh.write(f"{host} enter {time.time():.3f}\\n")
            fh.flush()
        time.sleep(hold)
        with open(marker, "a") as fh:
            fh.write(f"{host} exit {time.time():.3f}\\n")
            fh.flush()
    """
)


def _run_holder(lock_path, host, marker, hold):
    return subprocess.Popen(
        [sys.executable, "-c", _SUBPROC, str(CLASH_DIR / "clash_lock.py"),
         str(lock_path), host, str(marker), str(hold)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )


def test_two_hosts_never_overlap(lock_path, tmp_path):
    """Two processes with *different* host ids must not hold the lock at once."""
    marker = tmp_path / "intervals.txt"
    p1 = _run_holder(lock_path, "hostA", marker, 0.6)
    time.sleep(0.15)  # let hostA win the mkdir race
    p2 = _run_holder(lock_path, "hostB", marker, 0.0)
    out2, err2 = p2.communicate(timeout=45)
    out1, err1 = p1.communicate(timeout=45)
    assert p1.returncode == 0, err1
    assert p2.returncode == 0, err2

    events = [line.split() for line in marker.read_text().splitlines() if line.strip()]
    # events must be strictly enter/exit/enter/exit, never interleaved
    assert [e[1] for e in events] == ["enter", "exit", "enter", "exit"], events
    t0_exit = float(events[1][2])
    t1_enter = float(events[2][2])
    assert t1_enter >= t0_exit, "hostB entered before hostA exited"


def test_stale_foreign_lock_is_reclaimed(lock_path, monkeypatch):
    """A foreign holder that vanished is reclaimed within the window."""
    monkeypatch.setattr(cl, "STALE_AFTER", 0.3)
    monkeypatch.setattr(cl, "ACQUIRE_TIMEOUT", 10.0)
    monkeypatch.setenv("CLASH_LOCK_HOST_ID", "me")
    lock_dir = lock_path.parent / (lock_path.name + ".d")
    _holder(lock_dir, "deadhost", 999999)  # foreign + ancient

    started = time.monotonic()
    with cl.ClashConfigLock(lock_path):
        assert time.monotonic() - started >= 0.3
    assert not lock_dir.exists()


def test_fresh_foreign_lock_is_not_stolen(lock_path, monkeypatch):
    """A live foreign holder must cause a timeout, not a theft."""
    monkeypatch.setattr(cl, "STALE_AFTER", 60.0)
    monkeypatch.setattr(cl, "ACQUIRE_TIMEOUT", 0.4)
    monkeypatch.setenv("CLASH_LOCK_HOST_ID", "me")
    lock_dir = lock_path.parent / (lock_path.name + ".d")
    _holder(lock_dir, "livehost", 4242)

    with pytest.raises(TimeoutError):
        with cl.ClashConfigLock(lock_path):
            pass
    assert lock_dir.is_dir(), "must not delete a live foreign lock"
    assert "livehost|4242" in (lock_dir / "owner").read_text()


def test_dead_same_host_pid_is_reclaimed_at_once(lock_path, monkeypatch):
    """Same kernel → we can prove the holder is gone, so no lease wait."""
    monkeypatch.setattr(cl, "STALE_AFTER", 300.0)
    monkeypatch.setattr(cl, "ACQUIRE_TIMEOUT", 10.0)
    monkeypatch.setenv("CLASH_LOCK_HOST_ID", "me")
    lock_dir = lock_path.parent / (lock_path.name + ".d")
    # a pid that cannot be running
    dead_pid = 2 ** 22 + 12345
    _holder(lock_dir, "me", dead_pid)

    started = time.monotonic()
    with cl.ClashConfigLock(lock_path):
        pass
    assert time.monotonic() - started < 5.0


def test_lock_dir_without_token_is_reclaimed_after_grace(lock_path, monkeypatch):
    monkeypatch.setattr(cl, "MISSING_TOKEN_GRACE", 0.2)
    monkeypatch.setattr(cl, "ACQUIRE_TIMEOUT", 10.0)
    monkeypatch.setenv("CLASH_LOCK_HOST_ID", "me")
    lock_dir = lock_path.parent / (lock_path.name + ".d")
    lock_dir.mkdir(parents=True)  # crashed between mkdir and token write

    started = time.monotonic()
    with cl.ClashConfigLock(lock_path):
        assert time.monotonic() - started >= 0.2


def test_reclaim_rename_loses_the_race_gracefully(lock_path, monkeypatch):
    """If another host reclaims first, our reclaim is a no-op, not an error."""
    lock_dir = lock_path.parent / (lock_path.name + ".d")
    lock_dir.mkdir(parents=True)
    assert cl._reclaim(lock_dir) is True
    assert cl._reclaim(lock_dir) is False  # already gone


# --------------------------------------------------------------------------
# atomic write contract (unchanged by the lock rework)
# --------------------------------------------------------------------------

def test_atomic_write_preserves_mode_and_leaves_no_temp(tmp_path):
    target = tmp_path / "config.yaml"
    target.write_text("old\n", encoding="utf-8")
    target.chmod(0o664)

    cl.atomic_write_text(target, "new\n")

    assert target.read_text(encoding="utf-8") == "new\n"
    assert (target.stat().st_mode & 0o777) == 0o664
    assert not list(tmp_path.glob(".*.tmp-*"))
