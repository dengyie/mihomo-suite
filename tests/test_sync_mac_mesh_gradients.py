import importlib.util
from pathlib import Path

import pytest
import yaml

_PATH = Path(__file__).resolve().parents[1] / "scripts" / "sync-mac-mesh-gradients.py"
_spec = importlib.util.spec_from_file_location("sync_mac_mesh_gradients", _PATH)
smg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(smg)

SCRIPT = """const A = 1;
// @mesh-gradients:begin (stale)
const SELF_MESH_GRADIENTS = {
  "[自建] H1-梯度": "10.0.0.99",
};
// @mesh-gradients:end
const MESH_SUFFIX = "·mesh";
"""


def _spec_file(tmp_path, hosts):
    p = tmp_path / "mesh-gradients.yaml"
    p.write_text(yaml.safe_dump({"hosts": hosts}, allow_unicode=True), encoding="utf-8")
    return p


def test_sync_rewrites_only_marked_block_and_is_idempotent(tmp_path):
    spec = _spec_file(tmp_path, [
        {"name": "[自建] H1-梯度", "mesh-server": "10.0.0.1", "members": ["a"]},
        {"name": "[自建] H2-梯度", "mesh-server": "10.0.0.2", "members": ["b"]},
        {"name": "[自建] NoMesh-梯度", "members": ["c"]},
    ])
    script = tmp_path / "Script.js"
    script.write_text(SCRIPT, encoding="utf-8")
    assert smg.main(["--spec", str(spec), "--script", str(script), "--check"]) == 1
    assert smg.main(["--spec", str(spec), "--script", str(script)]) == 0
    out = script.read_text(encoding="utf-8")
    assert '"[自建] H1-梯度": "10.0.0.1",' in out and '"[自建] H2-梯度": "10.0.0.2",' in out
    assert "10.0.0.99" not in out and "NoMesh" not in out
    assert out.startswith("const A = 1;\n") and out.endswith('const MESH_SUFFIX = "·mesh";\n')
    assert smg.main(["--spec", str(spec), "--script", str(script), "--check"]) == 0


def test_sync_refuses_missing_or_duplicate_markers(tmp_path):
    spec = _spec_file(tmp_path, [{"name": "H", "mesh-server": "10.0.0.1", "members": ["a"]}])
    script = tmp_path / "Script.js"
    script.write_text("const SELF_MESH_GRADIENTS = {};\n", encoding="utf-8")
    assert smg.main(["--spec", str(spec), "--script", str(script)]) == 2
    with pytest.raises(ValueError):
        smg.sync(SCRIPT + SCRIPT, {"H": "10.0.0.1"})


def test_sync_rejects_spec_without_mesh_hosts(tmp_path):
    spec = _spec_file(tmp_path, [{"name": "H", "members": ["a"]}])
    script = tmp_path / "Script.js"
    script.write_text(SCRIPT, encoding="utf-8")
    assert smg.main(["--spec", str(spec), "--script", str(script)]) == 2
    assert script.read_text(encoding="utf-8") == SCRIPT
