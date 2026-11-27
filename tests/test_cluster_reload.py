from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
CLASH_DIR = ROOT_DIR / "clash"
if str(CLASH_DIR) not in sys.path:
    sys.path.insert(0, str(CLASH_DIR))

import cluster_reload


def _load_module_by_path(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def mock_clash_env(tmp_path, monkeypatch):
    clash_root = tmp_path / "clash"
    clash_root.mkdir(parents=True, exist_ok=True)
    zash_root = tmp_path / "zashboard"
    zash_root.mkdir(parents=True, exist_ok=True)
    personal_root = tmp_path / "personal"
    personal_root.mkdir(parents=True, exist_ok=True)

    (clash_root / ".controller-secret").write_text("test-controller-secret\n")
    (zash_root / "panel.password").write_text("test-panel-password\n")

    monkeypatch.setenv("CLASH_ROOT", str(clash_root))
    monkeypatch.setenv("PANEL_PASSWORD_FILE", str(zash_root / "panel.password"))
    monkeypatch.setenv("PERSONAL_ROOT", str(personal_root))

    monkeypatch.setattr(cluster_reload, "ROOT", clash_root)
    monkeypatch.setattr(cluster_reload, "PANEL_PASSWORD_FILE", zash_root / "panel.password")
    monkeypatch.setattr(cluster_reload, "CONTROLLER_SECRET_FILE", clash_root / ".controller-secret")
    monkeypatch.setattr(cluster_reload, "PERSONAL_ROOT", personal_root)
    return clash_root, zash_root, personal_root


def test_is_pxed_host_detection(monkeypatch):
    monkeypatch.setenv("NODE_NAME", "pxed")
    assert cluster_reload.is_pxed_host() is True

    monkeypatch.setenv("NODE_NAME", "tebi")
    assert cluster_reload.is_pxed_host() is False

    monkeypatch.delenv("NODE_NAME", raising=False)
    with patch("socket.gethostname", return_value="pxed-node-1"):
        with patch("os.path.exists", return_value=False):
            assert cluster_reload.is_pxed_host() is True

    with patch("socket.gethostname", return_value="tebi-node-1"):
        with patch("os.path.exists", return_value=False):
            assert cluster_reload.is_pxed_host() is False


def test_get_remote_node_ip(mock_clash_env):
    _, _, personal_root = mock_clash_env
    # Default fallbacks when no internal-ip file
    # pxed retired 2026-11-26: fast-fail address
    assert cluster_reload.get_remote_node_ip("pxed") == "0.0.0.0"
    # tebi: mesh address preferred when reachable, Bohrium LAN as fallback
    with patch.object(cluster_reload, "_mesh_reachable", return_value=True):
        assert cluster_reload.get_remote_node_ip("tebi") == "10.144.144.32"
    with patch.object(cluster_reload, "_mesh_reachable", return_value=False):
        assert cluster_reload.get_remote_node_ip("tebi") == "10.5.103.26"
    assert cluster_reload.get_remote_node_ip("other") == "127.0.0.1"

    # From internal-ip file
    ip_dir = personal_root / "pxed"
    ip_dir.mkdir(parents=True, exist_ok=True)
    (ip_dir / "internal-ip").write_text("10.5.103.99\n")
    assert cluster_reload.get_remote_node_ip("pxed") == "10.5.103.99"


def test_reload_local_success(mock_clash_env):
    clash_root, _, _ = mock_clash_env
    config_file = clash_root / "config.yaml"
    config_file.write_text("mode: rule\n")

    mock_resp = MagicMock()
    mock_resp.status = 204
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        status = cluster_reload.reload_local(config_path=config_file)
        assert status == 204
        req = mock_urlopen.call_args[0][0]
        assert req.get_method() == "PUT"
        assert req.full_url == "http://127.0.0.1:9090/configs?force=true"
        assert req.get_header("Authorization") == "Bearer test-controller-secret"
        payload = json.loads(req.data.decode("utf-8"))
        assert payload["path"] == str(config_file)


def test_reload_remote_peer_success(mock_clash_env, monkeypatch):
    monkeypatch.setenv("NODE_NAME", "tebi")  # local is tebi, peer is pxed
    clash_root, _, _ = mock_clash_env
    config_file = clash_root / "config.yaml"

    mock_resp = MagicMock()
    mock_resp.status = 204
    mock_resp.__enter__.return_value = mock_resp

    with patch.object(cluster_reload, "get_remote_node_ip", return_value="192.0.2.31"), \
            patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        res = cluster_reload.reload_remote_peer(config_path=config_file)
        assert res["success"] is True
        assert res["status"] == 204
        assert res["peer_node"] == "pxed"
        assert res["peer_ip"] == "192.0.2.31"
        assert res["error"] is None

        req = mock_urlopen.call_args[0][0]
        assert req.get_method() == "PUT"
        assert req.full_url == "http://192.0.2.31:2053/panel/api/configs?force=true"
        assert req.get_header("Authorization") == "Bearer test-panel-password"


def test_reload_remote_peer_failure_does_not_raise(mock_clash_env, monkeypatch):
    monkeypatch.setenv("NODE_NAME", "tebi")
    clash_root, _, _ = mock_clash_env
    config_file = clash_root / "config.yaml"

    with patch.object(cluster_reload, "get_remote_node_ip", return_value="192.0.2.31"), \
            patch("urllib.request.urlopen", side_effect=TimeoutError("Connection timed out")):
        res = cluster_reload.reload_remote_peer(config_path=config_file, timeout=2.0)
        assert res["success"] is False
        assert res["status"] is None
        assert res["peer_node"] == "pxed"
        assert "timed out" in res["error"]


def test_reload_remote_peer_loopback_guard(mock_clash_env, monkeypatch):
    monkeypatch.setenv("NODE_NAME", "tebi")
    with patch.object(cluster_reload, "get_remote_node_ip", return_value="127.0.0.1"):
        res = cluster_reload.reload_remote_peer()
        assert res["success"] is False
        assert "loopback" in res["error"]


@pytest.mark.parametrize("sentinel", ["0.0.0.0", "::", ""])
def test_reload_remote_peer_retired_peer_never_calls_out(mock_clash_env, monkeypatch, sentinel):
    """The retired pxed resolves to 0.0.0.0, which Linux routes to the local
    host: the PUT would force-reload our own kernel a second time."""
    monkeypatch.setenv("NODE_NAME", "tebi")
    with patch.object(cluster_reload, "get_remote_node_ip", return_value=sentinel), \
            patch("urllib.request.urlopen") as mock_urlopen:
        res = cluster_reload.reload_remote_peer()
        assert res["success"] is False
        assert "skipping remote call" in res["error"]
        mock_urlopen.assert_not_called()


def test_reload_remote_peer_missing_password_guard(mock_clash_env, monkeypatch):
    monkeypatch.setenv("NODE_NAME", "tebi")
    with patch.object(cluster_reload, "get_remote_node_ip", return_value="192.0.2.31"), \
            patch.object(cluster_reload, "get_panel_password", return_value=""):
        res = cluster_reload.reload_remote_peer()
        assert res["success"] is False
        assert "Missing panel password" in res["error"]


def test_reload_cluster_both_success(mock_clash_env, monkeypatch):
    monkeypatch.setenv("NODE_NAME", "tebi")
    with patch.object(cluster_reload, "reload_local", return_value=204) as mock_local:
        with patch.object(
            cluster_reload,
            "reload_remote_peer",
            return_value={"peer_node": "pxed", "peer_ip": "10.5.103.87", "status": 204, "success": True, "error": None},
        ) as mock_remote:
            res = cluster_reload.reload_cluster()
            assert res["local"]["success"] is True
            assert res["local"]["status"] == 204
            assert res["local"]["node"] == "tebi"
            assert res["remote"]["success"] is True
            assert res["remote"]["status"] == 204
            mock_local.assert_called_once()
            mock_remote.assert_called_once()


def test_reload_cluster_remote_down_still_succeeds(mock_clash_env, monkeypatch):
    monkeypatch.setenv("NODE_NAME", "tebi")
    with patch.object(cluster_reload, "reload_local", return_value=204):
        with patch.object(
            cluster_reload,
            "reload_remote_peer",
            return_value={"peer_node": "pxed", "peer_ip": "10.5.103.87", "status": None, "success": False, "error": "timed out"},
        ):
            res = cluster_reload.reload_cluster()
            assert res["local"]["success"] is True
            assert res["local"]["status"] == 204
            assert res["remote"]["success"] is False
            # reload_live should still return 204 because local succeeded
            live_status = cluster_reload.reload_live()
            assert live_status == 204


def test_reload_live_local_fail_raises(mock_clash_env):
    with patch.object(cluster_reload, "reload_local", side_effect=RuntimeError("Connection refused")):
        with patch.object(
            cluster_reload,
            "reload_remote_peer",
            return_value={"peer_node": "pxed", "peer_ip": "10.5.103.87", "status": 204, "success": True, "error": None},
        ):
            with pytest.raises(RuntimeError, match="Local reload failed"):
                cluster_reload.reload_live()


def test_apply_local_import_reload_live_integration():
    mod = _load_module_by_path("apply_local_import_test", CLASH_DIR / "apply-local-import.py")
    with patch("cluster_reload.reload_cluster") as mock_cluster:
        mock_cluster.return_value = {
            "local": {"node": "tebi", "status": 204, "success": True, "error": None},
            "remote": {"peer_node": "pxed", "peer_ip": "10.5.103.87", "status": 204, "success": True, "error": None},
        }
        status = mod.reload_live()
        assert status == 204
        mock_cluster.assert_called_once()


def test_rules_reconciler_reload_live_integration():
    mod = _load_module_by_path("rules_reconciler_test", CLASH_DIR / "rules-reconciler.py")
    with patch("cluster_reload.reload_cluster") as mock_cluster:
        mock_cluster.return_value = {
            "local": {"node": "tebi", "status": 204, "success": True, "error": None},
            "remote": {"peer_node": "pxed", "peer_ip": "10.5.103.87", "status": 204, "success": True, "error": None},
        }
        status = mod.reload_live()
        assert status == 204
        mock_cluster.assert_called_once()
