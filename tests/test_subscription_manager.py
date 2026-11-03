import base64
import importlib.util
import json
import socket
import sys
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent

# Dynamically import clash/subscription-manager.py
_sub_manager_path = ROOT / "clash" / "subscription-manager.py"
_spec = importlib.util.spec_from_file_location("subscription_manager", _sub_manager_path)
sm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sm)

DEFAULT_EXCLUDE_FILTER = sm.DEFAULT_EXCLUDE_FILTER
SubscriptionEngine = sm.SubscriptionEngine
ClashConfigLock = sm.ClashConfigLock
apply_node_name_prefix = sm.apply_node_name_prefix
decode_base64_safely = sm.decode_base64_safely
filter_nodes = sm.filter_nodes
is_safe_public_url = sm.is_safe_public_url
parse_hysteria2_uri = sm.parse_hysteria2_uri
parse_proxy_uri = sm.parse_proxy_uri
parse_raw_node_list = sm.parse_raw_node_list
parse_ss_uri = sm.parse_ss_uri
parse_subscription_content = sm.parse_subscription_content
parse_trojan_uri = sm.parse_trojan_uri
parse_vless_uri = sm.parse_vless_uri
parse_vmess_uri = sm.parse_vmess_uri
main = sm.main


@pytest.fixture
def temp_clash_root(tmp_path, monkeypatch):
    root = tmp_path / "clash_test"
    root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("CLASH_ROOT", str(root))
    return root


def test_decode_base64_safely():
    # Normal base64
    raw = "hello world"
    encoded = base64.b64encode(raw.encode()).decode()
    assert decode_base64_safely(encoded) == "hello world"

    # Missing padding 1, 2, 3
    unpadded = encoded.rstrip("=")
    assert decode_base64_safely(unpadded) == "hello world"

    # Bytes input
    assert decode_base64_safely(base64.b64encode(b"byte content")) == "byte content"

    # URL-safe characters
    raw_special = "subjects?test_value=1&other+value=2"
    encoded_urlsafe = base64.urlsafe_b64encode(raw_special.encode()).decode().rstrip("=")
    assert decode_base64_safely(encoded_urlsafe) == raw_special

    # Empty and invalid
    assert decode_base64_safely("") == ""


def test_parse_ss_uri():
    # Standard ss with base64 userinfo
    userinfo_b64 = base64.b64encode(b"aes-256-gcm:password123").decode()
    uri1 = f"ss://{userinfo_b64}@1.2.3.4:8388#Japan%2001"
    node1 = parse_ss_uri(uri1)
    assert node1 is not None
    assert node1["name"] == "Japan 01"
    assert node1["type"] == "ss"
    assert node1["server"] == "1.2.3.4"
    assert node1["port"] == 8388
    assert node1["cipher"] == "aes-256-gcm"
    assert node1["password"] == "password123"

    # Plain userinfo without base64
    uri_plain = "ss://aes-128-gcm:plainpass@1.2.3.4:8388#PlainSS"
    node_plain = parse_ss_uri(uri_plain)
    assert node_plain is not None
    assert node_plain["name"] == "PlainSS"
    assert node_plain["cipher"] == "aes-128-gcm"
    assert node_plain["password"] == "plainpass"

    # Legacy full base64 ss URI
    full_b64 = base64.b64encode(b"aes-128-gcm:pass@5.6.7.8:1080").decode()
    uri2 = f"ss://{full_b64}#US_Node"
    node2 = parse_ss_uri(uri2)
    assert node2 is not None
    assert node2["name"] == "US_Node"
    assert node2["server"] == "5.6.7.8"
    assert node2["port"] == 1080
    assert node2["cipher"] == "aes-128-gcm"
    assert node2["password"] == "pass"

    # IPv6 SS URI
    uri3 = f"ss://{userinfo_b64}@[2001:db8::1]:8388#IPv6-SS"
    node3 = parse_ss_uri(uri3)
    assert node3 is not None
    assert node3["server"] == "2001:db8::1"
    assert node3["port"] == 8388

    # SS with plugin
    uri4 = f"ss://{userinfo_b64}@1.2.3.4:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#Plugin-SS"
    node4 = parse_ss_uri(uri4)
    assert node4 is not None
    assert node4["plugin"] == "obfs-local"
    assert node4["plugin-opts"] == {"obfs": "http", "obfs-host": "example.com"}

    # Invalid SS URIs
    assert parse_ss_uri("ss://invalid") is None
    assert parse_ss_uri("ss://not-base64@") is None
    assert parse_ss_uri("trojan://pass@1.2.3.4:443") is None


def test_parse_vmess_uri():
    vmess_obj = {
        "v": "2",
        "ps": "HK-VMess-01",
        "add": "hk.example.com",
        "port": 443,
        "id": "a3b899b7-1234-4567-89ab-cdef01234567",
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": "cdn.example.com",
        "path": "/v2ray",
        "tls": "tls",
        "sni": "cdn.example.com",
    }
    raw_json = json.dumps(vmess_obj)
    b64_json = base64.b64encode(raw_json.encode()).decode()
    uri = f"vmess://{b64_json}"

    node = parse_vmess_uri(uri)
    assert node is not None
    assert node["name"] == "HK-VMess-01"
    assert node["type"] == "vmess"
    assert node["server"] == "hk.example.com"
    assert node["port"] == 443
    assert node["uuid"] == "a3b899b7-1234-4567-89ab-cdef01234567"
    assert node["cipher"] == "auto"
    assert node["network"] == "ws"
    assert node["tls"] is True
    assert node["servername"] == "cdn.example.com"
    assert node["ws-opts"] == {
        "path": "/v2ray",
        "headers": {"Host": "cdn.example.com"},
    }

    # gRPC vmess
    vmess_grpc = {
        "v": "2",
        "ps": "SG-gRPC",
        "add": "sg.example.com",
        "port": "8443",
        "id": "uuid-123",
        "net": "grpc",
        "path": "gunService",
        "tls": "1",
    }
    uri_grpc = f"vmess://{base64.b64encode(json.dumps(vmess_grpc).encode()).decode()}"
    node_grpc = parse_vmess_uri(uri_grpc)
    assert node_grpc is not None
    assert node_grpc["network"] == "grpc"
    assert node_grpc["grpc-opts"] == {"grpc-service-name": "gunService"}

    # H2 vmess
    vmess_h2 = {
        "v": "2",
        "ps": "US-H2",
        "add": "us.example.com",
        "port": 443,
        "id": "uuid-456",
        "net": "h2",
        "host": "h2.example.com",
        "path": "/h2path",
    }
    uri_h2 = f"vmess://{base64.b64encode(json.dumps(vmess_h2).encode()).decode()}"
    node_h2 = parse_vmess_uri(uri_h2)
    assert node_h2 is not None
    assert node_h2["network"] == "h2"
    assert node_h2["h2-opts"] == {"path": ["/h2path"], "host": ["h2.example.com"]}

    # Invalid vmess
    assert parse_vmess_uri("vmess://not-json") is None
    assert parse_vmess_uri("vless://test") is None


def test_parse_vless_uri():
    # VLESS Reality with pbk, sid, flow, sni
    uri = "vless://uuid-vless-123@vless.example.com:443?security=reality&encryption=none&pbk=publicKey123&sid=shortId12&sni=yahoo.com&type=tcp&flow=xtls-rprx-vision&fp=chrome#VLESS-Reality"
    node = parse_vless_uri(uri)
    assert node is not None
    assert node["name"] == "VLESS-Reality"
    assert node["type"] == "vless"
    assert node["server"] == "vless.example.com"
    assert node["port"] == 443
    assert node["uuid"] == "uuid-vless-123"
    assert node["flow"] == "xtls-rprx-vision"
    assert node["tls"] is True
    assert node["servername"] == "yahoo.com"
    assert node["client-fingerprint"] == "chrome"
    assert node["reality-opts"] == {
        "public-key": "publicKey123",
        "short-id": "shortId12",
    }

    # VLESS WS
    uri_ws = "vless://uuid-456@ws.example.com:80?type=ws&path=%2Fws-path&host=ws.example.com#VLESS-WS"
    node_ws = parse_vless_uri(uri_ws)
    assert node_ws is not None
    assert node_ws["network"] == "ws"
    assert node_ws["ws-opts"] == {
        "path": "/ws-path",
        "headers": {"Host": "ws.example.com"},
    }

    # VLESS gRPC
    uri_grpc = "vless://uuid-789@grpc.example.com:443?type=grpc&serviceName=vlessGun#VLESS-gRPC"
    node_grpc = parse_vless_uri(uri_grpc)
    assert node_grpc is not None
    assert node_grpc["network"] == "grpc"
    assert node_grpc["grpc-opts"] == {"grpc-service-name": "vlessGun"}

    # Invalid vless
    assert parse_vless_uri("vless://") is None
    assert parse_vless_uri("vmess://abc") is None


def test_parse_trojan_uri():
    uri = "trojan://password999@trojan.example.com:443?sni=tr.example.com&alpn=h2,http/1.1#Trojan-01"
    node = parse_trojan_uri(uri)
    assert node is not None
    assert node["name"] == "Trojan-01"
    assert node["type"] == "trojan"
    assert node["server"] == "trojan.example.com"
    assert node["port"] == 443
    assert node["password"] == "password999"
    assert node["sni"] == "tr.example.com"
    assert node["alpn"] == ["h2", "http/1.1"]

    # Trojan WS
    uri_ws = "trojan://pass@trojan.example.com:443?type=ws&path=/trojan-ws&host=tr.example.com#Trojan-WS"
    node_ws = parse_trojan_uri(uri_ws)
    assert node_ws is not None
    assert node_ws["network"] == "ws"
    assert node_ws["ws-opts"] == {"path": "/trojan-ws", "headers": {"Host": "tr.example.com"}}

    # Trojan gRPC
    uri_grpc = "trojan://pass@trojan.example.com:443?type=grpc&serviceName=trGun#Trojan-gRPC"
    node_grpc = parse_trojan_uri(uri_grpc)
    assert node_grpc is not None
    assert node_grpc["network"] == "grpc"
    assert node_grpc["grpc-opts"] == {"grpc-service-name": "trGun"}

    # Invalid trojan
    assert parse_trojan_uri("trojan://") is None
    assert parse_trojan_uri("ss://abc") is None


def test_parse_hysteria2_uri():
    uri = "hysteria2://mysecretpass@hy2.example.com:443?sni=hy2.example.com&insecure=1&obfs=salamander&obfs-password=123#Hy2-Node"
    node = parse_hysteria2_uri(uri)
    assert node is not None
    assert node["name"] == "Hy2-Node"
    assert node["type"] == "hysteria2"
    assert node["server"] == "hy2.example.com"
    assert node["port"] == 443
    assert node["password"] == "mysecretpass"
    assert node["sni"] == "hy2.example.com"
    assert node["skip-cert-verify"] is True
    assert node["obfs"] == "salamander"
    assert node["obfs-password"] == "123"

    # hy2:// alias
    uri_alias = "hy2://secret@hy2.example.com:8443?sni=hy2.example.com#Hy2-Alias"
    node_alias = parse_hysteria2_uri(uri_alias)
    assert node_alias is not None
    assert node_alias["type"] == "hysteria2"
    assert node_alias["port"] == 8443
    assert node_alias["password"] == "secret"

    # Invalid hysteria2
    assert parse_hysteria2_uri("hysteria2://") is None
    assert parse_hysteria2_uri("vless://abc") is None


def test_parse_proxy_uri_dispatch():
    assert parse_proxy_uri("unknown://test") is None
    assert parse_proxy_uri("") is None


def test_parse_subscription_content_yaml_and_base64():
    # Clash YAML subscription format
    yaml_content = """
proxies:
  - name: "Clash-SS"
    type: ss
    server: 1.1.1.1
    port: 8388
    cipher: aes-128-gcm
    password: pass
  - name: "Clash-Trojan"
    type: trojan
    server: 2.2.2.2
    port: 443
    password: pass
"""
    nodes_yaml = parse_subscription_content(yaml_content)
    assert len(nodes_yaml) == 2
    assert nodes_yaml[0]["name"] == "Clash-SS"
    assert nodes_yaml[1]["name"] == "Clash-Trojan"

    # Proxy keyword in YAML
    yaml_content_old = """
Proxy:
  - name: "Old-Clash-SS"
    type: ss
    server: 1.1.1.1
    port: 8388
    cipher: aes-128-gcm
    password: pass
"""
    nodes_yaml_old = parse_subscription_content(yaml_content_old)
    assert len(nodes_yaml_old) == 1
    assert nodes_yaml_old[0]["name"] == "Old-Clash-SS"

    # Base64 encoded list of URIs
    uris = [
        "trojan://pass@1.1.1.1:443#TrojanNode",
        "hy2://pass@2.2.2.2:8443#Hy2Node",
    ]
    b64_content = base64.b64encode("\n".join(uris).encode()).decode()
    nodes_b64 = parse_subscription_content(b64_content)
    assert len(nodes_b64) == 2
    assert nodes_b64[0]["name"] == "TrojanNode"
    assert nodes_b64[1]["name"] == "Hy2Node"

    # Empty content
    assert parse_subscription_content("") == []


def test_filter_nodes_and_prefix():
    raw_nodes = [
        {"name": "剩余流量 500GB", "type": "ss", "server": "1.1.1.1", "port": 80},
        {"name": "官网: https://example.com", "type": "ss", "server": "1.1.1.1", "port": 80},
        {"name": "HK 01", "type": "ss", "server": "1.1.1.1", "port": 8388},
        {"name": "US 02", "type": "vmess", "server": "2.2.2.2", "port": 443},
        {"name": "Invalid Node Missing Port", "type": "ss", "server": "3.3.3.3"},
    ]

    filtered = filter_nodes(raw_nodes)
    assert len(filtered) == 2
    assert [n["name"] for n in filtered] == ["HK 01", "US 02"]

    # Custom regex filter
    custom_filtered = filter_nodes(raw_nodes, exclude_pattern=r"HK")
    assert len(custom_filtered) == 3
    assert "HK 01" not in [n["name"] for n in custom_filtered]

    # Prefix application
    prefixed = apply_node_name_prefix(filtered, "AirportA")
    assert [n["name"] for n in prefixed] == ["[AirportA] HK 01", "[AirportA] US 02"]

    # Idempotent prefixing
    prefixed_again = apply_node_name_prefix(prefixed, "AirportA")
    assert [n["name"] for n in prefixed_again] == ["[AirportA] HK 01", "[AirportA] US 02"]


def test_subscription_engine_crud_and_reconcile(temp_clash_root):
    engine = SubscriptionEngine(root=temp_clash_root)

    # 1. Add raw nodes subscription
    raw_nodes_text = """
trojan://pass1@node1.com:443#Node1
trojan://pass2@node2.com:443#Node2
trojan://pass3@node3.com:443#官网-公告
"""
    res1 = engine.import_raw_nodes(name="Sub Raw", raw_text=raw_nodes_text)
    assert res1["success"] is True
    sub1_id = res1["subscription"]["id"]

    # Check meta file
    meta = engine.load_meta()
    assert len(meta["subscriptions"]) == 1
    assert meta["subscriptions"][0]["id"] == sub1_id
    assert meta["subscriptions"][0]["node_count"] == 2  # Announcement filtered

    # Check merged output yaml
    merged_path = temp_clash_root / "airports/airport-merged-sub.yaml"
    assert merged_path.exists()
    merged_data = yaml.safe_load(merged_path.read_text())
    assert len(merged_data["proxies"]) == 2
    assert merged_data["proxies"][0]["name"] == "[Sub Raw] Node1"
    assert merged_data["proxies"][1]["name"] == "[Sub Raw] Node2"

    # 2. Add remote subscription with mock fetch
    mock_yaml_content = """
proxies:
  - name: "Remote-HK"
    type: ss
    server: 8.8.8.8
    port: 8388
    cipher: aes-128-gcm
    password: mock
"""
    with patch.object(SubscriptionEngine, "fetch_url", return_value=mock_yaml_content):
        res2 = engine.add_subscription(name="Remote Sub", url="https://sub.example.com/api")
        assert res2["success"] is True
        sub2_id = res2["subscription"]["id"]

    # Total proxies should now be 2 (from sub1) + 1 (from sub2) = 3
    merged_data = yaml.safe_load(merged_path.read_text())
    assert len(merged_data["proxies"]) == 3
    names = [p["name"] for p in merged_data["proxies"]]
    assert "[Remote Sub] Remote-HK" in names

    # 3. Update subscription (disable sub1)
    res_update = engine.update_subscription(sub_id=sub1_id, enabled=False)
    assert res_update["success"] is True
    # Merged proxies should only contain Remote Sub now
    merged_data = yaml.safe_load(merged_path.read_text())
    assert len(merged_data["proxies"]) == 1
    assert merged_data["proxies"][0]["name"] == "[Remote Sub] Remote-HK"

    # 4. List subscriptions
    subs = engine.list_subscriptions()
    assert len(subs) == 2
    assert subs[0]["id"] == sub1_id
    assert subs[0]["enabled"] is False

    # 5. Delete subscription
    res_del = engine.delete_subscription(sub_id=sub2_id)
    assert res_del["success"] is True
    subs_after_del = engine.list_subscriptions()
    assert len(subs_after_del) == 1
    assert subs_after_del[0]["id"] == sub1_id

    # Merged proxies should be 0 because sub1 is disabled
    merged_data = yaml.safe_load(merged_path.read_text())
    assert len(merged_data["proxies"]) == 0

    # Non-existent delete
    res_bad_del = engine.delete_subscription("non-existent-id")
    assert res_bad_del["success"] is False


def test_duplicate_node_name_handling(temp_clash_root):
    engine = SubscriptionEngine(root=temp_clash_root)
    raw_nodes_text = """
trojan://pass1@node1.com:443#Hong Kong
trojan://pass2@node2.com:443#Hong Kong
"""
    engine.import_raw_nodes(name="Airport", raw_text=raw_nodes_text)
    merged_path = temp_clash_root / "airports/airport-merged-sub.yaml"
    merged_data = yaml.safe_load(merged_path.read_text())
    names = [p["name"] for p in merged_data["proxies"]]
    assert names == ["[Airport] Hong Kong", "[Airport] Hong Kong (1)"]


def test_config_lock_creates_and_reenters(temp_clash_root):
    lock_file = temp_clash_root / "subscriptions/.test.lock"
    with ClashConfigLock(lock_file):
        assert lock_file.exists()
        with ClashConfigLock(lock_file):  # nested acquisition must not self-deadlock
            assert lock_file.exists()


def test_config_lock_excludes_foreign_holder(temp_clash_root):
    """A second fd from outside the registry (i.e. another process) must wait."""
    import fcntl
    import threading
    import time

    lock_file = temp_clash_root / "subscriptions/.race.lock"
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    holder = open(lock_file, "a+")
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX)

    acquired = []
    try:
        def contender():
            with ClashConfigLock(lock_file):
                acquired.append(time.monotonic())

        t = threading.Thread(target=contender, daemon=True)
        started = time.monotonic()
        t.start()
        time.sleep(0.3)
        assert not acquired, "lock acquired while a foreign fd still held it"
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()
        holder = None
        t.join(timeout=5)
        assert acquired and acquired[0] >= started
    finally:
        if holder is not None:
            fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
            holder.close()


def test_cli_interface(temp_clash_root, monkeypatch, capsys):
    # Test --import-nodes CLI
    raw_nodes = "trojan://pass@node.com:443#TestNode"
    with patch.object(sys, "argv", ["subscription-manager.py", "--import-nodes", "CLI Sub", raw_nodes]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        captured = capsys.readouterr()
        assert '"success": true' in captured.out

    # Test --list CLI
    with patch.object(sys, "argv", ["subscription-manager.py", "--list"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        captured = capsys.readouterr()
        assert '"name": "CLI Sub"' in captured.out

    # Test --reconcile CLI
    with patch.object(sys, "argv", ["subscription-manager.py", "--reconcile"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        captured = capsys.readouterr()
        assert '"success": true' in captured.out


def test_ssrf_safety_checks(monkeypatch):
    # Scheme checks
    assert is_safe_public_url("file:///etc/passwd")[0] is False
    assert is_safe_public_url("gopher://127.0.0.1:6379")[0] is False
    assert is_safe_public_url("ftp://example.com/sub")[0] is False

    # IP address literals (private, loopback, link-local, cloud metadata)
    assert is_safe_public_url("http://127.0.0.1/sub.yaml")[0] is False
    assert is_safe_public_url("http://10.0.0.1:8080/sub")[0] is False
    assert is_safe_public_url("https://192.168.1.1/sub")[0] is False
    assert is_safe_public_url("http://172.16.0.5/sub")[0] is False
    assert is_safe_public_url("http://169.254.169.254/latest/meta-data/")[0] is False
    assert is_safe_public_url("http://0.0.0.0/sub")[0] is False
    assert is_safe_public_url("http://[::1]/sub")[0] is False

    # Mock domain resolution to private IP
    with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("127.0.0.1", 80))]):
        assert is_safe_public_url("http://localhost/sub")[0] is False
        assert is_safe_public_url("https://internal.company.corp/sub")[0] is False

    # Mock domain resolution to public IP
    with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("8.8.8.8", 443))]):
        assert is_safe_public_url("https://public-sub.com/clash")[0] is True

    # Test ALLOW_PRIVATE_SUBSCRIPTIONS env bypass
    monkeypatch.setenv("ALLOW_PRIVATE_SUBSCRIPTIONS", "1")
    assert is_safe_public_url("http://127.0.0.1/sub.yaml")[0] is True


def test_policy_group_auto_mount_and_consistency(temp_clash_root):
    # Setup initial live config with PROXY group and generic groups
    config_path = temp_clash_root / "config.yaml"
    initial_config = {
        'proxies': [
            {'name': 'Existing Direct Node', 'type': 'direct'}
        ],
        'proxy-groups': [
            {'name': 'PROXY', 'type': 'select', 'proxies': ['Existing Direct Node', 'DIRECT']},
            {'name': '🚀 节点选择', 'type': 'select', 'proxies': ['DIRECT']},
        ]
    }
    config_path.write_text(yaml.safe_dump(initial_config))

    engine = SubscriptionEngine(root=temp_clash_root)

    # 1. Import raw subscription nodes
    raw_nodes = "trojan://pass1@1.1.1.1:443#Hong Kong\ntrojan://pass2@2.2.2.2:443#Japan"
    res1 = engine.import_raw_nodes(name="Airport Alpha", raw_text=raw_nodes)
    assert res1["success"] is True

    # Check that config.yaml has been updated with '🌐 订阅导入' group and auto-mounted into PROXY & 🚀 节点选择
    cfg_data = yaml.safe_load(config_path.read_text())
    proxy_names = [p["name"] for p in cfg_data["proxies"]]
    assert "Existing Direct Node" in proxy_names
    assert "[Airport Alpha] Hong Kong" in proxy_names
    assert "[Airport Alpha] Japan" in proxy_names

    groups_map = {g["name"]: g for g in cfg_data["proxy-groups"]}
    assert "🌐 订阅导入" in groups_map
    assert groups_map["🌐 订阅导入"]["proxies"] == ["[Airport Alpha] Hong Kong", "[Airport Alpha] Japan"]

    assert "🌐 订阅导入" in groups_map["PROXY"]["proxies"]
    assert "🌐 订阅导入" in groups_map["🚀 节点选择"]["proxies"]

    # 2. Add second subscription
    raw_nodes_2 = "trojan://pass3@3.3.3.3:443#Singapore"
    res2 = engine.import_raw_nodes(name="Airport Beta", raw_text=raw_nodes_2)
    assert res2["success"] is True
    sub2_id = res2["subscription"]["id"]

    cfg_data2 = yaml.safe_load(config_path.read_text())
    groups_map2 = {g["name"]: g for g in cfg_data2["proxy-groups"]}
    assert "[Airport Beta] Singapore" in groups_map2["🌐 订阅导入"]["proxies"]

    # 3. Delete Airport Beta subscription -> node should be cleanly removed from proxies & groups
    engine.delete_subscription(sub2_id)
    cfg_data3 = yaml.safe_load(config_path.read_text())
    proxy_names3 = [p["name"] for p in cfg_data3["proxies"]]
    assert "[Airport Beta] Singapore" not in proxy_names3
    assert "[Airport Alpha] Hong Kong" in proxy_names3
    groups_map3 = {g["name"]: g for g in cfg_data3["proxy-groups"]}
    assert "[Airport Beta] Singapore" not in groups_map3["🌐 订阅导入"]["proxies"]


def test_prune_dead_nodes_and_disabled_filtering(temp_clash_root, monkeypatch):
    config_path = temp_clash_root / "config.yaml"
    initial_config = {
        'proxies': [
            {'name': 'GVPS-TUIC-googlevps', 'type': 'tuic'},
            {'name': 'Dead-Node-1', 'type': 'ss'},
            {'name': 'Alive-Node-1', 'type': 'ss'},
        ],
        'proxy-groups': [
            {'name': 'PROXY', 'type': 'select', 'proxies': ['GVPS-TUIC-googlevps', 'Dead-Node-1', 'Alive-Node-1']},
            {'name': '🌐 订阅导入', 'type': 'select', 'proxies': ['Dead-Node-1', 'Alive-Node-1']},
        ]
    }
    config_path.write_text(yaml.safe_dump(initial_config))

    engine = SubscriptionEngine(root=temp_clash_root)

    # Mock Mihomo controller /proxies and /proxies/{name}/delay endpoints
    def mock_urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, 'full_url') else req
        if "/proxies" in url and "/delay" not in url:
            # Return list of proxies
            data = {
                "proxies": {
                    "GVPS-TUIC-googlevps": {"type": "Tuic"},
                    "Dead-Node-1": {"type": "Shadowsocks"},
                    "Alive-Node-1": {"type": "Shadowsocks"},
                    "PROXY": {"type": "Selector"},
                }
            }
            body = json.dumps(data).encode("utf-8")
        elif "Dead-Node-1/delay" in url:
            raise urllib.error.URLError("Connection timeout")
        elif "Alive-Node-1/delay" in url:
            data = {"delay": 120}
            body = json.dumps(data).encode("utf-8")
        else:
            raise urllib.error.URLError("Not found")

        resp = MagicMock()
        resp.read.return_value = body
        resp.__enter__.return_value = resp
        resp.__exit__.return_value = None
        return resp

    monkeypatch.setattr(sm.urllib.request, "urlopen", mock_urlopen)

    res = engine.prune_dead_nodes(batch_size=5, max_workers=2, apply_filter=True)
    if not res.get("success"):
        print("DEBUG PRUNE ERROR:", res)
    assert res["success"] is True
    assert res["total_candidates"] == 2  # GVPS- is whitelisted, excluded!
    assert res["alive_count"] == 1
    assert res["dead_count"] == 1
    assert "Dead-Node-1" in res["newly_dead"]

    # Verify disabled-nodes.txt contains Dead-Node-1
    disabled_path = temp_clash_root / "airports/disabled-nodes.txt"
    assert disabled_path.exists()
    disabled_content = disabled_path.read_text()
    assert "Dead-Node-1" in disabled_content

    # Verify config.yaml was reconciled to exclude Dead-Node-1
    updated_cfg = yaml.safe_load(config_path.read_text())
    proxy_names = [p["name"] for p in updated_cfg["proxies"]]
    assert "Dead-Node-1" not in proxy_names
    assert "Alive-Node-1" in proxy_names
    assert "GVPS-TUIC-googlevps" in proxy_names

    # Verify proxy-groups cleaned
    groups_map = {g["name"]: g for g in updated_cfg["proxy-groups"]}
    assert "Dead-Node-1" not in groups_map["PROXY"]["proxies"]
    assert "Alive-Node-1" in groups_map["PROXY"]["proxies"]
    assert "GVPS-TUIC-googlevps" in groups_map["PROXY"]["proxies"]


def test_render_client_clash_config_includes_dns_and_local_nodes(temp_clash_root, monkeypatch):
    engine = SubscriptionEngine(root=temp_clash_root)
    (temp_clash_root / "airports").mkdir(parents=True, exist_ok=True)
    ss_alive = "ss://YWVzLTEyOC1nY206eA==@1.2.3.4:8388#Airport-Alive"
    ss_dead = "ss://YWVzLTEyOC1nY206eA==@5.6.7.8:8388#Airport-Dead"
    res = engine.import_raw_nodes(name="Airport", raw_text=f"{ss_alive}\n{ss_dead}")
    assert res["success"] is True
    (temp_clash_root / "airports" / "disabled-nodes.txt").write_text(
        "[Airport] Airport-Dead\n", encoding="utf-8"
    )
    (temp_clash_root / "airports" / "local-nodes.yaml").write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {
                        "name": "HK-Reality",
                        "type": "vless",
                        "server": "hk.example.com",
                        "port": 443,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    sentinel = temp_clash_root / "config.yaml"
    sentinel.write_text("proxies: []\nproxy-groups:\n- name: PROXY\n  type: select\n  proxies: [DIRECT]\n", encoding="utf-8")
    before = sentinel.read_text(encoding="utf-8")

    yaml_text = engine.render_client_clash_config(fetch_remote=False)
    doc = yaml.safe_load(yaml_text)
    names = [p["name"] for p in doc["proxies"]]
    assert "[Airport] Airport-Alive" in names
    assert "HK-Reality" in names
    assert "[Airport] Airport-Dead" not in names
    assert doc["dns"]["enhanced-mode"] == "fake-ip"
    assert "https://doh.pub/dns-query" in doc["dns"]["proxy-server-nameserver"]
    assert "+.argotunnel.com" in doc["dns"]["fake-ip-filter"]
    assert "DOMAIN-SUFFIX,mangoqwq.com,DIRECT" in doc["rules"]
    assert "DOMAIN-SUFFIX,meeting.tencent.com,DIRECT" in doc["rules"]
    assert "DOMAIN,stun.cloudflare.com,PROXY" in doc["rules"]
    assert "DST-PORT,3478,PROXY" in doc["rules"]
    assert "DOMAIN,accounts.google.com,🎯Google" in doc["rules"]
    assert "DOMAIN-SUFFIX,google.com,🎯Google" in doc["rules"]
    assert doc["rules"][-1] == "MATCH,PROXY"
    assert doc["tun"]["enable"] is True
    assert doc["tun"]["stack"] == "gvisor"
    assert doc["allow-lan"] is False
    assert "any:53" in doc["tun"]["dns-hijack"]
    groups = {g["name"]: g for g in doc["proxy-groups"]}
    assert groups["PROXY"]["type"] == "select"
    assert groups["AUTO"]["type"] == "url-test"
    assert groups["🎯Google"]["type"] == "select"
    assert "url" not in groups["🎯Google"]
    assert groups["🎯Google"]["proxies"] == ["PROXY"]
    assert "[Airport] Airport-Dead" not in groups["PROXY"]["proxies"]
    assert "HK-Reality" in groups["PROXY"]["proxies"]
    assert sentinel.read_text(encoding="utf-8") == before


def test_client_clash_export_webrtc_stun_and_media_rules_ordering(temp_clash_root):
    engine = SubscriptionEngine(root=temp_clash_root)
    (temp_clash_root / "airports").mkdir(parents=True, exist_ok=True)
    (temp_clash_root / "airports" / "local-nodes.yaml").write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {"name": "Node-A", "type": "ss", "server": "1.2.3.4", "port": 8388, "cipher": "aes-128-gcm", "password": "x"},
                ]
            }
        ),
        encoding="utf-8",
    )
    yaml_text = engine.render_client_clash_config(fetch_remote=False)
    errors = sm.validate_client_clash_yaml(yaml_text)
    assert errors == []

    doc = yaml.safe_load(yaml_text)
    rules = doc["rules"]

    # 1. Domestic media rules must be DIRECT
    media_rule = "DOMAIN-SUFFIX,meeting.tencent.com,DIRECT"
    assert media_rule in rules

    # 2. STUN rules must route to PROXY
    stun_domain_rule = "DOMAIN,stun.cloudflare.com,PROXY"
    stun_port_rule = "DST-PORT,3478,PROXY"
    assert stun_domain_rule in rules
    assert stun_port_rule in rules

    # 3. Cloudflare wildcard DIRECT rule
    cf_rule = "DOMAIN-SUFFIX,cloudflare.com,DIRECT"
    assert cf_rule in rules

    # 4. Strict priority ordering:
    # Domestic media < STUN rules < Cloudflare direct
    idx_media = rules.index(media_rule)
    idx_stun_domain = rules.index(stun_domain_rule)
    idx_stun_port = rules.index(stun_port_rule)
    idx_cf = rules.index(cf_rule)

    assert idx_media < idx_stun_domain
    assert idx_stun_domain < idx_cf
    assert idx_stun_port < idx_cf
    assert sm.CLIENT_EXPORT_RENDER_REV == "13"


def test_client_home_broadband_group_routes_hybgzs(temp_clash_root):
    engine = SubscriptionEngine(root=temp_clash_root)
    (temp_clash_root / "airports").mkdir(parents=True, exist_ok=True)
    (temp_clash_root / "airports" / "local-nodes.yaml").write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {"name": "🏠home-win-CF", "type": "vless", "server": "home.example.com", "port": 443},
                    {"name": "HK-Reality", "type": "vless", "server": "hk.example.com", "port": 443},
                ]
            }
        ),
        encoding="utf-8",
    )
    yaml_text = engine.render_client_clash_config(fetch_remote=False)
    assert sm.validate_client_clash_yaml(yaml_text) == []

    doc = yaml.safe_load(yaml_text)
    groups = {g["name"]: g for g in doc["proxy-groups"]}
    home = groups[sm.HOME_GROUP]
    assert home["type"] == "select"
    assert home["proxies"] == ["🏠home-win-CF", "DIRECT"]

    rule = "DOMAIN-SUFFIX,hybgzs.com,%s" % sm.HOME_GROUP
    assert rule in doc["rules"]
    # 家宽规则必须早于 MATCH 兜底
    assert doc["rules"].index(rule) < doc["rules"].index("MATCH,PROXY")


def test_client_home_group_prefers_tagged_home_win(temp_clash_root):
    engine = SubscriptionEngine(root=temp_clash_root)
    (temp_clash_root / "airports").mkdir(parents=True, exist_ok=True)
    (temp_clash_root / "airports" / "local-nodes.yaml").write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {"name": "[自建] 🏠home-win-CF", "type": "vless", "server": "home.example.com", "port": 443},
                    {"name": "[自建] VLESS-Azure-Reality", "type": "vless", "server": "2.2.2.2", "port": 443},
                ]
            }
        ),
        encoding="utf-8",
    )
    doc = yaml.safe_load(engine.render_client_clash_config(fetch_remote=False))
    groups = {g["name"]: g for g in doc["proxy-groups"]}
    assert groups[sm.HOME_GROUP]["proxies"] == ["[自建] 🏠home-win-CF", "DIRECT"]


def test_client_home_broadband_group_falls_back_to_direct_without_node(temp_clash_root):
    engine = SubscriptionEngine(root=temp_clash_root)
    (temp_clash_root / "airports").mkdir(parents=True, exist_ok=True)
    (temp_clash_root / "airports" / "local-nodes.yaml").write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {"name": "HK-Reality", "type": "vless", "server": "hk.example.com", "port": 443},
                ]
            }
        ),
        encoding="utf-8",
    )
    yaml_text = engine.render_client_clash_config(fetch_remote=False)
    assert sm.validate_client_clash_yaml(yaml_text) == []
    doc = yaml.safe_load(yaml_text)
    groups = {g["name"]: g for g in doc["proxy-groups"]}
    assert groups[sm.HOME_GROUP]["proxies"] == ["DIRECT"]


def test_client_google_group_uses_us_nodes_not_azure(temp_clash_root, monkeypatch):
    engine = SubscriptionEngine(root=temp_clash_root)
    (temp_clash_root / "airports").mkdir(parents=True, exist_ok=True)
    (temp_clash_root / "airports" / "local-nodes.yaml").write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {"name": "🇺🇸【北美洲】美国01原生丨直连【2x】", "type": "hysteria2", "server": "us.example.com", "port": 443},
                    {"name": "美国_BGP_A", "type": "anytls", "server": "bgp.example.com", "port": 443},
                    {"name": "美国高速 04| BGP", "type": "vless", "server": "bgp2.example.com", "port": 443},
                    {"name": "US-Los Angeles-435916-gtvs", "type": "vless", "server": "la.example.com", "port": 443},
                    {"name": "VLESS-Azure-Reality", "type": "vless", "server": "104.208.65.233", "port": 443},
                    {"name": "TUIC-googlevps", "type": "tuic", "server": "vps.example.com", "port": 443},
                    {"name": "🇭🇰【亚洲】香港01丨直连", "type": "vless", "server": "hk.example.com", "port": 443},
                ]
            }
        ),
        encoding="utf-8",
    )
    yaml_text = engine.render_client_clash_config(fetch_remote=False)
    doc = yaml.safe_load(yaml_text)
    groups = {g["name"]: g for g in doc["proxy-groups"]}
    google = groups["🎯Google"]["proxies"]
    assert "🇺🇸【北美洲】美国01原生丨直连【2x】" in google
    assert "美国_BGP_A" in google
    assert "美国高速 04| BGP" not in google
    assert "US-Los Angeles-435916-gtvs" not in google
    assert "VLESS-Azure-Reality" not in google
    assert "TUIC-googlevps" not in google
    assert "🇭🇰【亚洲】香港01丨直连" not in google


def test_client_export_drops_unresolved_dialer_proxy(temp_clash_root):
    engine = SubscriptionEngine(root=temp_clash_root)
    (temp_clash_root / "airports").mkdir(parents=True, exist_ok=True)
    (temp_clash_root / "airports" / "local-nodes.yaml").write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {
                        "name": "Keep-Direct",
                        "type": "ss",
                        "server": "1.2.3.4",
                        "port": 8388,
                    },
                    {
                        "name": "ZooProxy-HK",
                        "type": "http",
                        "server": "127.0.0.1",
                        "port": 44302,
                        "dialer-proxy": "AnyTLS-googlevps",
                    },
                    {
                        "name": "Chain-Mid",
                        "type": "http",
                        "server": "127.0.0.1",
                        "port": 1,
                        "dialer-proxy": "ZooProxy-HK",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    yaml_text = engine.render_client_clash_config(fetch_remote=False)
    doc = yaml.safe_load(yaml_text)
    names = [p["name"] for p in doc["proxies"]]
    assert names == ["Keep-Direct"]
    groups = {g["name"]: g for g in doc["proxy-groups"]}
    assert "ZooProxy-HK" not in groups["PROXY"]["proxies"]
    assert "Chain-Mid" not in groups["AUTO"]["proxies"]
    assert "AnyTLS-googlevps" not in yaml_text


def test_save_local_nodes_file_keeps_simple_groups(temp_clash_root):
    path = temp_clash_root / "airports" / "local-nodes.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    sm.save_local_nodes_file(
        path,
        [
            {"name": "Alive-A", "type": "ss", "server": "1.2.3.4", "port": 1, "_probe": "ok"},
            {"name": "VPS-B", "type": "vless", "server": "5.6.7.8", "port": 443},
            {"name": "Dead-C", "type": "ss", "server": "9.9.9.9", "port": 1},
        ],
        groups={"vps-import": ["VPS-B", "Dead-C", "Missing"], "google": ["Alive-A"]},
    )
    sm.save_local_nodes_file(
        path,
        [
            {"name": "Alive-A", "type": "ss", "server": "1.2.3.4", "port": 1},
            {"name": "VPS-B", "type": "vless", "server": "5.6.7.8", "port": 443},
        ],
    )
    doc = yaml.safe_load(path.read_text())
    assert [p["name"] for p in doc["proxies"]] == ["Alive-A", "VPS-B"]
    assert "_probe" not in doc["proxies"][0]
    assert doc["groups"]["vps-import"] == ["VPS-B"]
    assert doc["groups"]["google"] == ["Alive-A"]


def test_client_google_group_uses_simple_groups_list(temp_clash_root):
    engine = SubscriptionEngine(root=temp_clash_root)
    (temp_clash_root / "airports").mkdir(parents=True, exist_ok=True)
    (temp_clash_root / "airports" / "local-nodes.yaml").write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {"name": "Pinned-US", "type": "hysteria2", "server": "us.example.com", "port": 443},
                    {"name": "美国_BGP_A", "type": "anytls", "server": "bgp.example.com", "port": 443},
                    {"name": "VLESS-Azure-Reality", "type": "vless", "server": "104.208.65.233", "port": 443},
                ],
                "groups": {"google": ["Pinned-US"]},
            }
        ),
        encoding="utf-8",
    )
    yaml_text = engine.render_client_clash_config(fetch_remote=False)
    doc = yaml.safe_load(yaml_text)
    google_group = {g["name"]: g for g in doc["proxy-groups"]}["🎯Google"]
    assert google_group["type"] == "select"
    assert google_group["proxies"] == ["Pinned-US"]


def test_skip_merge_subscription_stays_out_of_merged(temp_clash_root, monkeypatch):
    engine = SubscriptionEngine(root=temp_clash_root)
    ss = "ss://YWVzLTEyOC1nY206eA==@1.2.3.4:8388#Skip-Me"
    res = engine.add_subscription(
        name="LocalLive",
        sub_type="raw",
        raw_content=ss,
        skip_merge=True,
    )
    assert res["success"] is True
    merged = yaml.safe_load((temp_clash_root / "airports" / "airport-merged-sub.yaml").read_text())
    names = [p["name"] for p in (merged.get("proxies") or [])]
    assert names == []
    listed = engine.list_subscriptions()
    assert listed[0]["skip_merge"] is True
    assert listed[0]["node_count"] == 1
    sentinel = temp_clash_root / "config.yaml"
    sentinel.write_text(
        "proxies:\n- name: Keep-Me\n  type: ss\n  server: 1.1.1.1\n  port: 1\n"
        "proxy-groups:\n- name: PROXY\n  type: select\n  proxies: [Keep-Me]\n",
        encoding="utf-8",
    )
    before = sentinel.read_text(encoding="utf-8")
    engine.reconcile_merged(fetch_remote=False, update_targets=True)
    assert sentinel.read_text(encoding="utf-8") == before


def test_fetch_url_refuses_redirects(temp_clash_root, monkeypatch):
    engine = SubscriptionEngine(root=temp_clash_root)
    assert engine.root == temp_clash_root
    with patch.object(sm, "is_safe_public_url", return_value=(True, "")):
        with patch.object(
            sm,
            "_http_get_pinned",
            return_value=(302, {"location": "http://127.0.0.1/secret"}, b"", "1.2.3.4"),
        ):
            with pytest.raises(ValueError, match="redirect refused"):
                engine.fetch_url("https://public-sub.example/clash")


def test_fetch_url_proxy_fallback_success(temp_clash_root, monkeypatch):
    engine = SubscriptionEngine(root=temp_clash_root)
    with patch.object(sm, "is_safe_public_url", return_value=(True, "")):
        with patch.object(sm, "_http_get_pinned", side_effect=TimeoutError("handshake timeout")):
            with patch.object(
                sm,
                "_http_get_via_proxy",
                return_value=(200, {}, b"proxies:\n- name: SG\n  type: vless\n  server: 1.2.3.4\n"),
            ) as mock_proxy:
                content = engine.fetch_url("https://overseas-sub.example/clash")
                assert "SG" in content
                mock_proxy.assert_called_once()


def test_fetch_url_proxy_fallback_failure(temp_clash_root, monkeypatch):
    engine = SubscriptionEngine(root=temp_clash_root)
    with patch.object(sm, "is_safe_public_url", return_value=(True, "")):
        with patch.object(sm, "_http_get_pinned", side_effect=TimeoutError("handshake timeout")):
            with patch.object(
                sm,
                "_http_get_via_proxy",
                side_effect=ConnectionRefusedError("proxy down"),
            ):
                with pytest.raises(ValueError, match="Fetch failed"):
                    engine.fetch_url("https://overseas-sub.example/clash")


def test_fetch_url_proxy_disabled_env(temp_clash_root, monkeypatch):
    monkeypatch.setenv("SUB_FETCH_PROXY", "none")
    engine = SubscriptionEngine(root=temp_clash_root)
    with patch.object(sm, "is_safe_public_url", return_value=(True, "")):
        with patch.object(sm, "_http_get_pinned", side_effect=TimeoutError("handshake timeout")):
            with patch.object(sm, "_http_get_via_proxy") as mock_proxy:
                with pytest.raises(TimeoutError, match="handshake timeout"):
                    engine.fetch_url("https://overseas-sub.example/clash")
                mock_proxy.assert_not_called()


def test_http_get_via_proxy_schemeless_normalization():
    with patch("http.client.HTTPSConnection") as mock_conn_cls:
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.getheaders.return_value = [("content-type", "text/yaml")]
        mock_resp.read.side_effect = [b"proxies: []", b""]
        mock_conn.getresponse.return_value = mock_resp
        mock_conn_cls.return_value = mock_conn

        status, headers, body = sm._http_get_via_proxy(
            url="https://example.com/clash.yaml",
            proxy_url="127.0.0.1:7897",
            timeout=10,
            user_agent="test-agent",
        )

        mock_conn_cls.assert_called_once()
        args, kwargs = mock_conn_cls.call_args
        assert args[0] == "127.0.0.1"
        assert args[1] == 7897
        mock_conn.set_tunnel.assert_called_once_with("example.com", 443, headers={"User-Agent": "test-agent"})
        assert status == 200
        assert body == b"proxies: []"


def test_fetch_url_proxy_fallback_logs(temp_clash_root, monkeypatch, caplog):
    import logging
    monkeypatch.setenv("SUB_FETCH_PROXY", "127.0.0.1:7897")
    engine = SubscriptionEngine(root=temp_clash_root)
    with caplog.at_level(logging.INFO):
        with patch.object(sm, "is_safe_public_url", return_value=(True, "")):
            with patch.object(sm, "_http_get_pinned", side_effect=TimeoutError("handshake timeout")):
                with patch.object(
                    sm,
                    "_http_get_via_proxy",
                    return_value=(200, {}, b"proxies: []"),
                ) as mock_proxy:
                    content = engine.fetch_url("https://overseas-sub.example/clash")
                    assert content == "proxies: []"
                    mock_proxy.assert_called_once_with(
                        "https://overseas-sub.example/clash",
                        proxy_url="127.0.0.1:7897",
                        timeout=15,
                        user_agent="ClashMeta/v1.18.0 mihomo/1.18.0",
                    )
                    assert any("falling back to proxy 127.0.0.1:7897" in record.message for record in caplog.records)


def test_fetch_url_caps_body(temp_clash_root, monkeypatch):
    class _Huge:
        def read(self, n):
            return b"x" * n

    with pytest.raises(ValueError, match="size limit"):
        sm._read_capped(_Huge(), 8)


def test_get_or_create_client_token_env_wins(temp_clash_root, monkeypatch):
    monkeypatch.setenv("CLIENT_SUB_TOKEN", "pinned-from-env")
    engine = SubscriptionEngine(root=temp_clash_root)
    assert engine.get_or_create_client_token() == "pinned-from-env"


def test_get_or_create_client_token_file_is_group_readable(temp_clash_root, monkeypatch):
    monkeypatch.delenv("CLIENT_SUB_TOKEN", raising=False)
    engine = SubscriptionEngine(root=temp_clash_root)
    token = engine.get_or_create_client_token()
    path = temp_clash_root / "subscriptions" / "client-export.token"
    assert path.read_text(encoding="utf-8").strip() == token
    mode = path.stat().st_mode & 0o777
    assert mode == 0o640


def test_get_or_create_client_token_repairs_owner_only_mode(temp_clash_root, monkeypatch):
    monkeypatch.delenv("CLIENT_SUB_TOKEN", raising=False)
    path = temp_clash_root / "subscriptions" / "client-export.token"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("existing-token\n", encoding="utf-8")
    path.chmod(0o600)
    engine = SubscriptionEngine(root=temp_clash_root)
    assert engine.get_or_create_client_token() == "existing-token"
    assert (path.stat().st_mode & 0o777) == 0o640


def test_inject_alive_into_local_nodes_skips_dead(temp_clash_root, monkeypatch):
    engine = SubscriptionEngine(root=temp_clash_root)
    ss_alive = "ss://YWVzLTEyOC1nY206eA==@1.2.3.4:8388#Keep"
    ss_dead = "ss://YWVzLTEyOC1nY206eA==@5.6.7.8:8388#Drop"
    sentinel = temp_clash_root / "config.yaml"
    sentinel.write_text("proxies: []\n", encoding="utf-8")
    before = sentinel.read_text(encoding="utf-8")

    def fake_probe(nodes, timeout=1.5, max_workers=8, keep_ssrf=False):
        alive = [n for n in nodes if "Keep" in str(n.get("name"))]
        dead = [n for n in nodes if "Drop" in str(n.get("name"))]
        return alive, dead

    monkeypatch.setattr(sm, "probe_nodes", fake_probe)
    res = engine.add_subscription(
        name="Pool",
        sub_type="raw",
        raw_content=f"{ss_alive}\n{ss_dead}",
        skip_merge=True,
        inject_local=True,
        probe=True,
    )
    assert res["success"] is True
    assert res["inject"]["injected"] == 1
    assert res["inject"]["dead"] == 1
    local = yaml.safe_load((temp_clash_root / "airports" / "local-nodes.yaml").read_text())
    names = [p["name"] for p in local["proxies"]]
    assert names == ["[Pool] Keep"]
    disabled_path = temp_clash_root / "airports" / "disabled-nodes.txt"
    disabled_text = disabled_path.read_text() if disabled_path.exists() else ""
    assert "[Pool] Drop" not in disabled_text
    assert sentinel.read_text(encoding="utf-8") == before


def test_prune_local_node_file_writes_denylist(temp_clash_root, monkeypatch):
    engine = SubscriptionEngine(root=temp_clash_root)
    (temp_clash_root / "airports").mkdir(parents=True, exist_ok=True)
    (temp_clash_root / "airports" / "local-nodes.yaml").write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {"name": "Alive-A", "type": "ss", "server": "1.2.3.4", "port": 1},
                    {"name": "Dead-B", "type": "ss", "server": "5.6.7.8", "port": 1},
                    {"name": "UDP-C", "type": "tuic", "server": "9.9.9.9", "port": 443},
                ]
            }
        ),
        encoding="utf-8",
    )
    sentinel = temp_clash_root / "config.yaml"
    sentinel.write_text("proxies:\n- name: Keep-VPS\n  type: ss\n  server: 1.1.1.1\n  port: 1\n", encoding="utf-8")
    before = sentinel.read_text(encoding="utf-8")

    def fake_probe(nodes, timeout=1.5, max_workers=8, keep_ssrf=False):
        alive, dead = [], []
        for n in nodes:
            if n["name"] == "Dead-B":
                dead.append(n)
            else:
                alive.append(n)
        return alive, dead

    monkeypatch.setattr(sm, "probe_nodes", fake_probe)
    res = engine.prune_local_node_file(apply_filter=True)
    assert res["success"] is True
    assert res["dead_count"] == 1
    assert "Dead-B" in res["newly_dead"]
    local = yaml.safe_load((temp_clash_root / "airports" / "local-nodes.yaml").read_text())
    names = [p["name"] for p in local["proxies"]]
    assert "Alive-A" in names
    assert "UDP-C" in names
    assert "Dead-B" not in names
    assert "Dead-B" in (temp_clash_root / "airports" / "disabled-nodes.txt").read_text()
    assert sentinel.read_text(encoding="utf-8") == before


def test_udp_node_types_skip_tcp_probe():
    ok, reason = sm.probe_node_tcp({"name": "hy", "type": "hysteria2", "server": "1.2.3.4", "port": 443})
    assert ok is True
    assert reason == "udp-skip"


def test_probe_node_tcp_rejects_private_without_connecting():
    ok, reason = sm.probe_node_tcp({"name": "lan", "type": "ss", "server": "127.0.0.1", "port": 8388})
    assert ok is False
    assert reason == sm.PROBE_REASON_SSRF


def test_probe_nodes_keep_ssrf_on_prune():
    node = {"name": "lan", "type": "ss", "server": "10.0.0.1", "port": 8388}
    alive, dead = sm.probe_nodes([node], keep_ssrf=True)
    assert [n["name"] for n in alive] == ["lan"]
    assert dead == []
    alive2, dead2 = sm.probe_nodes([node], keep_ssrf=False)
    assert alive2 == []
    assert [n["name"] for n in dead2] == ["lan"]


def test_ipv6_node_skips_tcp_probe_when_no_ipv6_route(monkeypatch):
    monkeypatch.setattr(sm, "has_ipv6_route", lambda force_check=False: False)
    node = {"name": "v6-node", "type": "vless", "server": "2606:4700:4700::1111", "port": 443}
    ok, reason = sm.probe_node_tcp(node)
    assert ok is True
    assert reason == "ipv6-skip"


def test_pin_resolved_ip_prefers_ipv4_when_no_ipv6_route(monkeypatch):
    monkeypatch.setattr(sm, "has_ipv6_route", lambda force_check=False: False)
    fake_addr_infos = [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700:4700::1111", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 0)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: fake_addr_infos)
    pinned = sm._pin_resolved_ip("dual-stack.example.com", allow_private=False)
    assert pinned == "1.1.1.1"


def test_inject_alive_into_local_nodes_with_target_group(temp_clash_root, monkeypatch):
    engine = sm.SubscriptionEngine(root=temp_clash_root)
    (temp_clash_root / "airports").mkdir(parents=True, exist_ok=True)
    (temp_clash_root / "airports" / "local-nodes.yaml").write_text(
        yaml.safe_dump({
            "proxies": [{"name": "Old-VPS", "type": "ss", "server": "9.9.9.9", "port": 1}],
            "groups": {"vps-import": ["Old-VPS"]}
        }),
        encoding="utf-8"
    )

    nodes = [
        {"name": "New-IPv4", "type": "ss", "server": "1.2.3.4", "port": 8388, "_probe": "tcp-ok"},
        {"name": "New-IPv6", "type": "ss", "server": "2606::1", "port": 8388, "_probe": "ipv6-skip"},
    ]
    res = engine._inject_alive_into_local_nodes(nodes, probe=False, target_group="vps-import")
    assert res["injected"] == 2
    local_doc = sm.load_local_nodes_document(temp_clash_root / "airports" / "local-nodes.yaml")
    proxy_names = [p["name"] for p in local_doc["proxies"]]
    assert "New-IPv4" in proxy_names
    assert "New-IPv6" in proxy_names
    # Only IPv4 is added to vps-import; ipv6-skip is excluded from vps-import
    assert local_doc["groups"]["vps-import"] == ["Old-VPS", "New-IPv4"]


def test_add_subscription_defaults_target_group_and_filter(temp_clash_root, monkeypatch):
    engine = sm.SubscriptionEngine(root=temp_clash_root)
    # Pass empty exclude_filter and no target_group with inject_local=True
    res = engine.add_subscription(
        name="AutoGroupSub",
        url="",
        sub_type="raw",
        raw_content="proxies:\n- name: AutoNode\n  type: ss\n  server: 1.2.3.4\n  port: 8388\n- name: 剩余流量：100GB\n  type: ss\n  server: 1.2.3.4\n  port: 8388\n",
        exclude_filter="  ",
        skip_merge=True,
        inject_local=True,
        probe=False,
    )
    assert res["success"] is True
    meta = engine.load_meta()
    sub = next(s for s in meta["subscriptions"] if s["name"] == "AutoGroupSub")
    assert sub["target_group"] == "vps-import"
    assert sub["exclude_filter"] == sm.DEFAULT_EXCLUDE_FILTER
    # Traffic dummy node should be filtered out
    assert sub["node_count"] == 1
    local_doc = sm.load_local_nodes_document(temp_clash_root / "airports" / "local-nodes.yaml")
    assert "[AutoGroupSub] AutoNode" in local_doc["groups"]["vps-import"]
    assert "[AutoGroupSub] 剩余流量：100GB" not in [p["name"] for p in local_doc["proxies"]]


def test_update_subscription_target_group_and_filter(temp_clash_root):
    engine = sm.SubscriptionEngine(root=temp_clash_root)
    res = engine.add_subscription(
        name="SubToUpdate",
        sub_type="raw",
        raw_content="proxies:\n- name: N1\n  type: ss\n  server: 1.2.3.4\n  port: 8388\n",
        skip_merge=False,
        inject_local=False,
    )
    sub_id = res["subscription"]["id"]
    up_res = engine.update_subscription(
        sub_id=sub_id,
        target_group="custom-group",
        exclude_filter="  ",
    )
    assert up_res["success"] is True
    assert up_res["subscription"]["target_group"] == "custom-group"
    assert up_res["subscription"]["exclude_filter"] == sm.DEFAULT_EXCLUDE_FILTER


def test_delete_subscription_retracts_injected_nodes(temp_clash_root):
    engine = sm.SubscriptionEngine(root=temp_clash_root)
    (temp_clash_root / "airports").mkdir(parents=True, exist_ok=True)
    (temp_clash_root / "airports" / "local-nodes.yaml").write_text(
        yaml.safe_dump({
            "proxies": [
                {"name": "Keep-VPS", "type": "ss", "server": "9.9.9.9", "port": 1},
            ],
            "groups": {"vps-import": ["Keep-VPS"]},
        }),
        encoding="utf-8",
    )
    res = engine.add_subscription(
        name="RetractSub",
        sub_type="raw",
        raw_content="proxies:\n- name: N1\n  type: ss\n  server: 1.2.3.4\n  port: 8388\n",
        skip_merge=True,
        inject_local=True,
        probe=False,
    )
    assert res["success"] is True
    local_doc = sm.load_local_nodes_document(temp_clash_root / "airports" / "local-nodes.yaml")
    assert "[RetractSub] N1" in local_doc["groups"]["vps-import"]

    del_res = engine.delete_subscription(res["subscription"]["id"])
    assert del_res["success"] is True
    assert del_res["retracted"] == 1
    local_doc = sm.load_local_nodes_document(temp_clash_root / "airports" / "local-nodes.yaml")
    names = [p["name"] for p in local_doc["proxies"]]
    assert "[RetractSub] N1" not in names
    assert "Keep-VPS" in names
    assert local_doc["groups"]["vps-import"] == ["Keep-VPS"]


def test_rename_subscription_retracts_old_prefixed_nodes(temp_clash_root):
    engine = sm.SubscriptionEngine(root=temp_clash_root)
    res = engine.add_subscription(
        name="OldName",
        sub_type="raw",
        raw_content="proxies:\n- name: N1\n  type: ss\n  server: 1.2.3.4\n  port: 8388\n",
        skip_merge=True,
        inject_local=True,
        probe=False,
    )
    sub_id = res["subscription"]["id"]
    local_doc = sm.load_local_nodes_document(temp_clash_root / "airports" / "local-nodes.yaml")
    assert "[OldName] N1" in local_doc["groups"]["vps-import"]

    up_res = engine.update_subscription(sub_id=sub_id, name="NewName")
    assert up_res["success"] is True
    local_doc = sm.load_local_nodes_document(temp_clash_root / "airports" / "local-nodes.yaml")
    names = [p["name"] for p in local_doc["proxies"]]
    assert "[OldName] N1" not in names
    assert local_doc["groups"].get("vps-import", []) == []


def test_apply_local_import_auto_exclude_bk_prefix_only():
    ali = _load_apply_local_import()
    # `bk-` is a prefix marker, not a substring: names merely containing it stay.
    assert ali.is_auto_excluded("BK-US-01") is True
    assert ali.is_auto_excluded("bk-vps") is True
    assert ali.is_auto_excluded("ABK-US-01") is False
    assert ali.is_auto_excluded("node-bk-1") is False
    assert ali.is_auto_excluded("JP-Reality") is False
    assert ali.is_auto_excluded("VLESS-Azure-Reality") is True
    assert ali.is_auto_excluded("Mac-Reverse-17897") is True
    assert ali.is_auto_excluded("🏠home-win-CF") is True


def test_apply_local_import_removes_orphaned_subscription_nodes(temp_clash_root, monkeypatch, capsys):
    """A deleted subscription's injected nodes must stop persisting in config."""
    airports = temp_clash_root / "airports"
    airports.mkdir(parents=True, exist_ok=True)
    (airports / "local-nodes.yaml").write_text(
        yaml.safe_dump(
            {
                "proxies": [{"name": "Keep-VPS", "type": "ss", "server": "9.9.9.9", "port": 1}],
                "groups": {"vps-import": ["Keep-VPS"]},
            }
        ),
        encoding="utf-8",
    )
    cfg = temp_clash_root / "config.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {"name": "Keep-VPS", "type": "ss", "server": "9.9.9.9", "port": 1},
                    # Orphan: prefix present, name no longer in vps-import.
                    {"name": "[DelMe] Orphan", "type": "ss", "server": "8.8.4.4", "port": 8388},
                    # Normal hand-managed node: keeps its place.
                    {"name": "Totally-Normal", "type": "ss", "server": "1.1.1.1", "port": 80},
                ],
                "proxy-groups": [
                    {"name": "PROXY", "type": "select", "proxies": ["Keep-VPS", "[DelMe] Orphan", "Totally-Normal"]},
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("APPLY_LOCAL_IMPORT_FILE", raising=False)
    monkeypatch.setenv("CLASH_ROOT", str(temp_clash_root))
    ali = _load_apply_local_import()
    ali.ROOT = temp_clash_root
    ali.main()
    doc = yaml.safe_load(cfg.read_text())
    names = [p["name"] for p in doc["proxies"]]
    assert "[DelMe] Orphan" not in names
    assert "Keep-VPS" in names
    assert "Totally-Normal" in names
    groups = {g["name"]: g for g in doc["proxy-groups"]}
    assert groups["PROXY"]["proxies"] == ["Keep-VPS", "Totally-Normal"]


def _load_apply_local_import():
    path = ROOT / "clash" / "apply-local-import.py"
    spec = importlib.util.spec_from_file_location("apply_local_import", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_apply_local_import_skips_without_vps_group(temp_clash_root, monkeypatch, capsys):
    airports = temp_clash_root / "airports"
    airports.mkdir(parents=True, exist_ok=True)
    (airports / "local-nodes.yaml").write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {"name": "All-A", "type": "ss", "server": "1.1.1.1", "port": 1},
                    {"name": "All-B", "type": "ss", "server": "2.2.2.2", "port": 1},
                ]
            }
        ),
        encoding="utf-8",
    )
    cfg = temp_clash_root / "config.yaml"
    cfg.write_text(
        "proxies:\n- name: Keep-VPS\n  type: ss\n  server: 1.1.1.1\n  port: 1\n"
        "proxy-groups:\n- name: 🌐 本机导入\n  type: select\n  proxies: [Keep-VPS]\n",
        encoding="utf-8",
    )
    before = cfg.read_text()
    monkeypatch.delenv("APPLY_LOCAL_IMPORT_FILE", raising=False)
    monkeypatch.setenv("CLASH_ROOT", str(temp_clash_root))
    ali = _load_apply_local_import()
    ali.ROOT = temp_clash_root
    ali.main()
    out = capsys.readouterr().out
    assert "no groups.vps-import" in out
    assert cfg.read_text() == before


def test_apply_local_import_uses_vps_import_subset(temp_clash_root, monkeypatch, capsys):
    airports = temp_clash_root / "airports"
    airports.mkdir(parents=True, exist_ok=True)
    (airports / "local-nodes.yaml").write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {"name": "Pool-A", "type": "ss", "server": "1.1.1.1", "port": 1},
                    {"name": "VPS-Only", "type": "vless", "server": "2.2.2.2", "port": 443},
                    {"name": "Pool-C", "type": "ss", "server": "3.3.3.3", "port": 1},
                ],
                "groups": {"vps-import": ["VPS-Only"], "google": ["Pool-A"]},
            }
        ),
        encoding="utf-8",
    )
    cfg = temp_clash_root / "config.yaml"
    cfg.write_text(
        "proxies:\n- name: Keep-VPS\n  type: ss\n  server: 9.9.9.9\n  port: 1\n"
        "proxy-groups:\n- name: 🌐 本机导入\n  type: select\n  proxies: [Keep-VPS]\n"
        "- name: PROXY\n  type: select\n  proxies: [Keep-VPS]\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("APPLY_LOCAL_IMPORT_FILE", raising=False)
    monkeypatch.setenv("CLASH_ROOT", str(temp_clash_root))
    ali = _load_apply_local_import()
    ali.ROOT = temp_clash_root
    ali.main()
    doc = yaml.safe_load(cfg.read_text())
    names = [p["name"] for p in doc["proxies"]]
    assert "VPS-Only" in names
    assert "Pool-A" not in names
    assert "Pool-C" not in names
    groups = {g["name"]: g for g in doc["proxy-groups"]}
    assert groups["🌐 本机导入"]["proxies"] == ["VPS-Only"]
    assert groups["PROXY"]["proxies"] == ["Keep-VPS"]


def test_apply_local_import_purges_third_party_nodes(temp_clash_root, monkeypatch, capsys):
    airports = temp_clash_root / "airports"
    airports.mkdir(parents=True, exist_ok=True)
    (airports / "local-nodes.yaml").write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {"name": "Valid-VPS", "type": "vless", "server": "2.2.2.2", "port": 443},
                ],
                "groups": {"vps-import": ["Valid-VPS"]},
            }
        ),
        encoding="utf-8",
    )
    cfg = temp_clash_root / "config.yaml"
    cfg.write_text(
        "proxies:\n"
        "- name: SUB-Airport-Node-1\n  type: ss\n  server: 1.1.1.1\n  port: 1\n"
        "- name: JX-Airport-Node-2\n  type: ss\n  server: 1.1.1.2\n  port: 2\n"
        "- name: GL-Airport-Node-3\n  type: ss\n  server: 1.1.1.3\n  port: 3\n"
        "- name: JS-Airport-Node-4\n  type: ss\n  server: 1.1.1.4\n  port: 4\n"
        "- name: KQ-Airport-Node-5\n  type: ss\n  server: 1.1.1.5\n  port: 5\n"
        "- name: 续费备用节点\n  type: ss\n  server: 1.1.1.6\n  port: 6\n"
        "- name: Normal-Node\n  type: ss\n  server: 1.1.1.7\n  port: 7\n"
        "proxy-groups:\n"
        "- name: 🌐 本机导入\n  type: select\n  proxies: [SUB-Airport-Node-1]\n"
        "- name: 🔰ChatGPT\n  type: select\n  proxies: [SUB-Airport-Node-1, JX-Airport-Node-2]\n"
        "- name: PROXY\n  type: select\n  proxies: [Normal-Node, SUB-Airport-Node-1]\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("APPLY_LOCAL_IMPORT_FILE", raising=False)
    monkeypatch.setenv("CLASH_ROOT", str(temp_clash_root))
    ali = _load_apply_local_import()
    ali.ROOT = temp_clash_root
    ali.main()
    doc = yaml.safe_load(cfg.read_text())
    names = [p["name"] for p in doc["proxies"]]
    assert "Valid-VPS" in names
    assert "Normal-Node" in names
    for bad in ["SUB-Airport-Node-1", "JX-Airport-Node-2", "GL-Airport-Node-3", "JS-Airport-Node-4", "KQ-Airport-Node-5", "续费备用节点"]:
        assert bad not in names
    groups = {g["name"]: g for g in doc["proxy-groups"]}
    assert groups["🌐 本机导入"]["proxies"] == ["Valid-VPS"]
    assert groups["🔰ChatGPT"]["proxies"] == ["PROXY"]
    assert groups["PROXY"]["proxies"] == ["Normal-Node"]


def test_apply_local_import_enrolls_into_proxy_and_auto_when_no_local_group(temp_clash_root, monkeypatch):
    airports = temp_clash_root / "airports"
    airports.mkdir(parents=True, exist_ok=True)
    (airports / "local-nodes.yaml").write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {"name": "Tomorin-1", "type": "vless", "server": "2.2.2.2", "port": 443},
                ],
                "groups": {"vps-import": ["Tomorin-1"]},
            }
        ),
        encoding="utf-8",
    )
    cfg = temp_clash_root / "config.yaml"
    cfg.write_text(
        "proxies:\n"
        "- name: Existing-Node\n  type: ss\n  server: 1.1.1.7\n  port: 7\n"
        "proxy-groups:\n"
        "- name: PROXY\n  type: select\n  proxies: [Existing-Node]\n"
        "- name: AUTO\n  type: url-test\n  proxies: [Existing-Node]\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("APPLY_LOCAL_IMPORT_FILE", raising=False)
    monkeypatch.setenv("CLASH_ROOT", str(temp_clash_root))
    ali = _load_apply_local_import()
    ali.ROOT = temp_clash_root
    ali.main()
    doc = yaml.safe_load(cfg.read_text())
    names = [p["name"] for p in doc["proxies"]]
    assert "Tomorin-1" in names
    assert "Existing-Node" in names
    groups = {g["name"]: g for g in doc["proxy-groups"]}
    assert "Tomorin-1" in groups["PROXY"]["proxies"]
    assert "Tomorin-1" in groups["AUTO"]["proxies"]


def test_apply_local_import_sanitizes_special_groups(temp_clash_root, monkeypatch):
    airports = temp_clash_root / "airports"
    airports.mkdir(parents=True, exist_ok=True)
    (airports / "local-nodes.yaml").write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {"name": "Regular-Node", "type": "ss", "server": "1.1.1.1", "port": 443},
                    {"name": "VLESS-Azure-Reality", "type": "vless", "server": "2.2.2.2", "port": 443},
                    {"name": "BK-US-01", "type": "ss", "server": "3.3.3.3", "port": 443},
                    {"name": "🏠home-win-CF", "type": "vless", "server": "4.4.4.4", "port": 443},
                ],
                "groups": {
                    "vps-import": ["Regular-Node", "VLESS-Azure-Reality", "BK-US-01", "🏠home-win-CF"]
                },
            }
        ),
        encoding="utf-8",
    )
    cfg = temp_clash_root / "config.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {"name": "Mac-Reverse-17897", "type": "socks5", "server": "127.0.0.1", "port": 17897},
                ],
                "proxy-groups": [
                    {"name": "PROXY", "type": "select", "proxies": ["Mac-Reverse-17897"]},
                    {"name": "AUTO", "type": "url-test", "proxies": ["Mac-Reverse-17897", "🏠home-win-CF", "VLESS-Azure-Reality"]},
                    {"name": "cpa-clean-egress", "type": "select", "proxies": ["Mac-Reverse-17897", "PROXY", "DIRECT"]},
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("APPLY_LOCAL_IMPORT_FILE", raising=False)
    monkeypatch.setenv("CLASH_ROOT", str(temp_clash_root))
    ali = _load_apply_local_import()
    ali.ROOT = temp_clash_root
    ali.main()
    doc = yaml.safe_load(cfg.read_text())
    groups = {g["name"]: g for g in doc["proxy-groups"]}

    # PROXY should not have Mac-Reverse-17897
    assert "Mac-Reverse-17897" not in groups["PROXY"]["proxies"]
    assert "Regular-Node" in groups["PROXY"]["proxies"]

    # AUTO should only have regular nodes; no Azure, no Reverse, no home-win, no BK-
    assert "Regular-Node" in groups["AUTO"]["proxies"]
    assert "Mac-Reverse-17897" not in groups["AUTO"]["proxies"]
    assert "🏠home-win-CF" not in groups["AUTO"]["proxies"]
    assert "VLESS-Azure-Reality" not in groups["AUTO"]["proxies"]
    assert "BK-US-01" not in groups["AUTO"]["proxies"]

    # cpa-clean-egress should have 🏠home-win-CF at the front, and no reverse/17897 nodes
    assert groups["cpa-clean-egress"]["proxies"][0] == "🏠home-win-CF"
    assert "Mac-Reverse-17897" not in groups["cpa-clean-egress"]["proxies"]


def _run_apply_local_import(temp_clash_root, monkeypatch):
    monkeypatch.delenv("APPLY_LOCAL_IMPORT_FILE", raising=False)
    monkeypatch.setenv("CLASH_ROOT", str(temp_clash_root))
    ali = _load_apply_local_import()
    ali.ROOT = temp_clash_root
    ali.main()
    return ali


def test_apply_local_import_mirrors_self_tag_onto_config(temp_clash_root, monkeypatch):
    """A bare node present in the pool as [自建] X is renamed, refs follow."""
    airports = temp_clash_root / "airports"
    airports.mkdir(parents=True, exist_ok=True)
    (airports / "local-nodes.yaml").write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {"name": "[自建] VLESS-Azure-Reality", "type": "vless", "server": "2.2.2.2", "port": 443},
                    {
                        "name": "[自建] TUIC-googlevps",
                        "type": "tuic",
                        "server": "3.3.3.3",
                        "port": 443,
                        "dialer-proxy": "[自建] AnyTLS-googlevps",
                    },
                    {"name": "[自建] AnyTLS-googlevps", "type": "anytls", "server": "3.3.3.3", "port": 8443},
                ],
                "groups": {"vps-import": ["[自建] VLESS-Azure-Reality"]},
            }
        ),
        encoding="utf-8",
    )
    cfg = temp_clash_root / "config.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {"name": "VLESS-Azure-Reality", "type": "vless", "server": "2.2.2.2", "port": 443},
                    {
                        "name": "TUIC-googlevps",
                        "type": "tuic",
                        "server": "3.3.3.3",
                        "port": 443,
                        "dialer-proxy": "AnyTLS-googlevps",
                    },
                    {
                        "name": "Some-Node",
                        "type": "ss",
                        "server": "9.9.9.9",
                        "port": 1,
                        "dialer-proxy": "VLESS-Azure-Reality",
                    },
                ],
                "proxy-groups": [
                    {"name": "PROXY", "type": "select", "proxies": ["VLESS-Azure-Reality", "Some-Node"]},
                ],
                "listeners": [
                    {"name": "l1", "type": "mixed", "port": 10818, "proxy": "VLESS-Azure-Reality"},
                ],
                "rules": ["IN-USER,zen_key_2,VLESS-Azure-Reality", "MATCH,PROXY"],
            }
        ),
        encoding="utf-8",
    )
    _run_apply_local_import(temp_clash_root, monkeypatch)
    doc = yaml.safe_load(cfg.read_text())
    names = [p["name"] for p in doc["proxies"]]
    assert "[自建] VLESS-Azure-Reality" in names
    assert "VLESS-Azure-Reality" not in names
    assert "[自建] TUIC-googlevps" in names

    proxies = {p["name"]: p for p in doc["proxies"]}
    assert proxies["Some-Node"]["dialer-proxy"] == "[自建] VLESS-Azure-Reality"
    assert proxies["[自建] TUIC-googlevps"]["dialer-proxy"] == "[自建] AnyTLS-googlevps"
    groups = {g["name"]: g for g in doc["proxy-groups"]}
    assert "VLESS-Azure-Reality" not in groups["PROXY"]["proxies"]
    assert "[自建] VLESS-Azure-Reality" in groups["PROXY"]["proxies"]
    assert doc["listeners"][0]["proxy"] == "[自建] VLESS-Azure-Reality"
    assert doc["rules"][0] == "IN-USER,zen_key_2,[自建] VLESS-Azure-Reality"


def test_apply_local_import_retires_bare_twin_of_tagged_node(temp_clash_root, monkeypatch):
    """Both bare and tagged copies on the same upstream -> keep only the tagged."""
    airports = temp_clash_root / "airports"
    airports.mkdir(parents=True, exist_ok=True)
    (airports / "local-nodes.yaml").write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {"name": "[自建] TUIC-Azure", "type": "tuic", "server": "4.4.4.4", "port": 443},
                ],
                "groups": {"vps-import": ["[自建] TUIC-Azure"]},
            }
        ),
        encoding="utf-8",
    )
    cfg = temp_clash_root / "config.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {"name": "TUIC-Azure", "type": "tuic", "server": "4.4.4.4", "port": 443},
                    {"name": "[自建] TUIC-Azure", "type": "tuic", "server": "4.4.4.4", "port": 443},
                    # Same bare name but a different upstream: must not be touched.
                    {"name": "TUIC-Azure", "type": "tuic", "server": "5.5.5.5", "port": 443},
                ],
                "proxy-groups": [
                    {"name": "PROXY", "type": "select", "proxies": ["TUIC-Azure", "[自建] TUIC-Azure"]},
                ],
            }
        ),
        encoding="utf-8",
    )
    _run_apply_local_import(temp_clash_root, monkeypatch)
    doc = yaml.safe_load(cfg.read_text())
    names = [p["name"] for p in doc["proxies"]]
    assert names.count("[自建] TUIC-Azure") == 1
    # The bare name on a different upstream is left untouched (not our node).
    assert "TUIC-Azure" in names
    servers = [p["server"] for p in doc["proxies"] if p["name"] == "[自建] TUIC-Azure"]
    assert servers == ["4.4.4.4"]


def test_apply_local_import_keeps_self_tagged_orphan(temp_clash_root, monkeypatch):
    """[自建] nodes are hand-managed and must survive the orphan sweep."""
    airports = temp_clash_root / "airports"
    airports.mkdir(parents=True, exist_ok=True)
    (airports / "local-nodes.yaml").write_text(
        yaml.safe_dump(
            {
                "proxies": [{"name": "Keep-VPS", "type": "ss", "server": "9.9.9.9", "port": 1}],
                "groups": {"vps-import": ["Keep-VPS"]},
            }
        ),
        encoding="utf-8",
    )
    cfg = temp_clash_root / "config.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {"name": "Keep-VPS", "type": "ss", "server": "9.9.9.9", "port": 1},
                    {"name": "[自建] Hand-Made", "type": "vless", "server": "1.2.3.4", "port": 443},
                    {"name": "[DelMe] Orphan", "type": "ss", "server": "8.8.4.4", "port": 8388},
                ],
                "proxy-groups": [
                    {"name": "PROXY", "type": "select", "proxies": ["Keep-VPS", "[自建] Hand-Made", "[DelMe] Orphan"]},
                ],
            }
        ),
        encoding="utf-8",
    )
    _run_apply_local_import(temp_clash_root, monkeypatch)
    doc = yaml.safe_load(cfg.read_text())
    names = [p["name"] for p in doc["proxies"]]
    assert "[自建] Hand-Made" in names
    assert "[DelMe] Orphan" not in names
    groups = {g["name"]: g for g in doc["proxy-groups"]}
    assert groups["PROXY"]["proxies"] == ["Keep-VPS", "[自建] Hand-Made"]


def test_add_remote_fetch_failure_is_not_success(temp_clash_root):
    engine = SubscriptionEngine(root=temp_clash_root)
    with patch.object(SubscriptionEngine, "fetch_url", side_effect=ValueError("HTTP 500")):
        res = engine.add_subscription(name="Down", url="https://sub.example.com/clash")
    assert res["success"] is False
    assert str(res["error"]).startswith("Fetch failed")
    assert res["subscription"]["last_error"].startswith("Fetch failed")


def test_update_refresh_fetches_outside_lock_and_injects(temp_clash_root, monkeypatch):
    import fcntl

    engine = SubscriptionEngine(root=temp_clash_root)
    yaml_v1 = """
proxies:
  - name: Keep
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-128-gcm
    password: x
"""
    yaml_v2 = """
proxies:
  - name: Keep
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-128-gcm
    password: x
  - name: Extra
    type: ss
    server: 5.6.7.8
    port: 8388
    cipher: aes-128-gcm
    password: x
"""
    with patch.object(SubscriptionEngine, "fetch_url", return_value=yaml_v1):
        added = engine.add_subscription(
            name="Pool",
            url="https://sub.example.com/clash",
            skip_merge=True,
            inject_local=False,
        )
    sub_id = added["subscription"]["id"]
    lock_held_during_fetch = []

    def fake_fetch(url):
        with open(engine.lock_file, "a") as fh:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                lock_held_during_fetch.append(False)
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except BlockingIOError:
                lock_held_during_fetch.append(True)
        return yaml_v2

    def fake_probe(nodes, timeout=1.5, max_workers=8, keep_ssrf=False):
        return list(nodes), []

    monkeypatch.setattr(sm, "probe_nodes", fake_probe)
    with patch.object(SubscriptionEngine, "fetch_url", side_effect=fake_fetch):
        res = engine.update_subscription(sub_id=sub_id, refresh=True)
    assert lock_held_during_fetch == [False]
    assert res["success"] is True
    assert res["inject"]["injected"] == 2
    local = yaml.safe_load((temp_clash_root / "airports" / "local-nodes.yaml").read_text())
    names = [p["name"] for p in local["proxies"]]
    assert "[Pool] Keep" in names
    assert "[Pool] Extra" in names


def test_update_refresh_fetch_failure_is_not_success(temp_clash_root):
    engine = SubscriptionEngine(root=temp_clash_root)
    yaml_ok = """
proxies:
  - name: Keep
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-128-gcm
    password: x
"""
    with patch.object(SubscriptionEngine, "fetch_url", return_value=yaml_ok):
        added = engine.add_subscription(
            name="Pool",
            url="https://sub.example.com/clash",
            skip_merge=True,
            inject_local=False,
        )
    sub_id = added["subscription"]["id"]
    with patch.object(SubscriptionEngine, "fetch_url", side_effect=ValueError("HTTP 502")):
        res = engine.update_subscription(sub_id=sub_id, refresh=True)
    assert res["success"] is False
    assert str(res["error"]).startswith("Fetch failed")


def test_inject_caps_probe_candidates(temp_clash_root, monkeypatch):
    engine = SubscriptionEngine(root=temp_clash_root)
    lines = [
        f"ss://YWVzLTEyOC1nY206eA==@1.2.3.{i}:8388#N{i}"
        for i in range(1, 6)
    ]
    seen = []

    def fake_probe(nodes, timeout=1.5, max_workers=8, keep_ssrf=False):
        seen.append(len(nodes))
        return list(nodes), []

    monkeypatch.setattr(sm, "NODE_PROBE_MAX_CANDIDATES", 2)
    monkeypatch.setattr(sm, "probe_nodes", fake_probe)
    res = engine.add_subscription(
        name="Cap",
        sub_type="raw",
        raw_content="\n".join(lines),
        skip_merge=True,
        inject_local=True,
        probe=True,
    )
    assert seen == [2]
    assert res["inject"]["truncated"] is True
    assert res["inject"]["probed"] == 2


def test_prune_skips_replaced_endpoint(temp_clash_root, monkeypatch):
    engine = SubscriptionEngine(root=temp_clash_root)
    airports = temp_clash_root / "airports"
    airports.mkdir(parents=True, exist_ok=True)
    (airports / "local-nodes.yaml").write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {"name": "Same", "type": "ss", "server": "5.6.7.8", "port": 1},
                ]
            }
        ),
        encoding="utf-8",
    )

    def fake_probe(nodes, timeout=1.5, max_workers=8, keep_ssrf=False):
        (airports / "local-nodes.yaml").write_text(
            yaml.safe_dump(
                {
                    "proxies": [
                        {"name": "Same", "type": "ss", "server": "9.9.9.9", "port": 443},
                    ]
                }
            ),
            encoding="utf-8",
        )
        return [], list(nodes)

    monkeypatch.setattr(sm, "probe_nodes", fake_probe)
    res = engine.prune_local_node_file(apply_filter=True)
    assert res["success"] is True
    assert res["dead_count"] == 0
    assert res["skipped_replaced"] == 1
    local = yaml.safe_load((airports / "local-nodes.yaml").read_text())
    assert local["proxies"][0]["server"] == "9.9.9.9"
    disabled = (airports / "disabled-nodes.txt").read_text() if (airports / "disabled-nodes.txt").exists() else ""
    assert "Same" not in disabled


def test_hy2_uri_emits_hysteria2_type():
    node = parse_hysteria2_uri("hy2://secret@1.2.3.4:443#Hy")
    assert node is not None
    assert node["type"] == "hysteria2"
    ok, reason = sm.probe_node_tcp(node)
    assert ok is True
    assert reason == "udp-skip"


def _minimal_client_yaml(extra_proxies=None, extra_group_members=None):
    proxies = [
        {
            "name": "Keep-Direct",
            "type": "ss",
            "server": "1.2.3.4",
            "port": 8388,
            "cipher": "aes-128-gcm",
            "password": "x",
        }
    ]
    if extra_proxies:
        proxies.extend(extra_proxies)
    names = [p["name"] for p in proxies]
    members = names + (extra_group_members or [])
    doc = {
        "mixed-port": 7897,
        "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["AUTO"] + members + ["DIRECT"]},
            {"name": "AUTO", "type": "url-test", "proxies": members or ["DIRECT"]},
            {"name": "🎯Google", "type": "url-test", "proxies": ["PROXY"]},
        ],
        "rules": ["MATCH,PROXY"],
    }
    return yaml.safe_dump(doc, allow_unicode=True)


def test_validate_client_clash_yaml_rejects_dangling_dialer():
    text = _minimal_client_yaml(
        extra_proxies=[
            {
                "name": "ZooProxy-HK",
                "type": "http",
                "server": "127.0.0.1",
                "port": 44302,
                "dialer-proxy": "AnyTLS-googlevps",
            }
        ]
    )
    errors = sm.validate_client_clash_yaml(text)
    assert any("dialer-proxy" in e and "AnyTLS-googlevps" in e for e in errors)


def test_validate_client_clash_yaml_rejects_missing_group_member():
    text = _minimal_client_yaml(extra_group_members=["Ghost-Node"])
    errors = sm.validate_client_clash_yaml(text)
    assert any("Ghost-Node" in e for e in errors)


def test_validate_client_clash_yaml_accepts_clean_export():
    errors = sm.validate_client_clash_yaml(_minimal_client_yaml())
    assert errors == []


def test_publish_invalid_render_does_not_overwrite_last_good(temp_clash_root, monkeypatch):
    engine = SubscriptionEngine(root=temp_clash_root)
    (temp_clash_root / "airports").mkdir(parents=True, exist_ok=True)
    (temp_clash_root / "airports" / "local-nodes.yaml").write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {
                        "name": "Keep-Direct",
                        "type": "ss",
                        "server": "1.2.3.4",
                        "port": 8388,
                        "cipher": "aes-128-gcm",
                        "password": "x",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    first = engine.publish_client_clash_config(fetch_remote=False)
    assert first["published"] is True
    assert first["served_last_good"] is False
    last_path = temp_clash_root / "airports" / "mango-clash.yaml"
    before = last_path.read_text(encoding="utf-8")
    digest = first["sha256"]

    def broken_render(fetch_remote=False):
        return _minimal_client_yaml(
            extra_proxies=[
                {
                    "name": "ZooProxy-HK",
                    "type": "http",
                    "server": "127.0.0.1",
                    "port": 1,
                    "dialer-proxy": "AnyTLS-googlevps",
                }
            ]
        )

    monkeypatch.setattr(engine, "render_client_clash_config", broken_render)
    monkeypatch.setattr(engine, "_client_export_inputs_fingerprint", lambda: "force-rerender")
    second = engine.publish_client_clash_config(fetch_remote=False)
    assert second["published"] is False
    assert second["served_last_good"] is True
    assert second["sha256"] == digest
    assert last_path.read_text(encoding="utf-8") == before
    assert any("dialer-proxy" in e for e in second["errors"])


def test_publish_without_last_good_raises(temp_clash_root, monkeypatch):
    engine = SubscriptionEngine(root=temp_clash_root)
    monkeypatch.setattr(
        engine,
        "render_client_clash_config",
        lambda fetch_remote=False: "proxies: []\nproxy-groups: []\n",
    )
    with pytest.raises(sm.ClientExportInvalid):
        engine.publish_client_clash_config(fetch_remote=False)
    assert not (temp_clash_root / "airports" / "mango-clash.yaml").exists()


def test_publish_merged_missing_does_not_drop_subscription_nodes(temp_clash_root, monkeypatch):
    """A missing merged file is an anomaly and must serve last-good, never a
    node-poor export that would silently pass validation and overwrite it."""
    engine = SubscriptionEngine(root=temp_clash_root)
    (temp_clash_root / "airports").mkdir(parents=True, exist_ok=True)
    (temp_clash_root / "airports" / "local-nodes.yaml").write_text(
        yaml.safe_dump({"proxies": [
            {"name": "Keep-Direct", "type": "ss", "server": "1.2.3.4", "port": 8388,
             "cipher": "aes-128-gcm", "password": "x"}]}),
        encoding="utf-8",
    )
    first = engine.publish_client_clash_config(fetch_remote=False)
    assert first["published"] is True
    last_path = temp_clash_root / "airports" / "mango-clash.yaml"
    before = last_path.read_text(encoding="utf-8")
    digest = first["sha256"]

    def noop_reconcile(**kwargs):
        return {}

    monkeypatch.setattr(engine, "reconcile_merged", noop_reconcile)
    monkeypatch.setattr(engine, "_client_export_inputs_fingerprint", lambda: "force-rerender")
    merged_path = temp_clash_root / "airports" / "airport-merged-sub.yaml"
    assert merged_path.exists()
    merged_path.unlink()
    second = engine.publish_client_clash_config(fetch_remote=False)
    assert second["published"] is False
    assert second["served_last_good"] is True
    assert second["sha256"] == digest
    assert last_path.read_text(encoding="utf-8") == before


def test_publish_merged_corrupt_does_not_drop_subscription_nodes(temp_clash_root, monkeypatch):
    engine = SubscriptionEngine(root=temp_clash_root)
    (temp_clash_root / "airports").mkdir(parents=True, exist_ok=True)
    (temp_clash_root / "airports" / "local-nodes.yaml").write_text(
        yaml.safe_dump({"proxies": [
            {"name": "Keep-Direct", "type": "ss", "server": "1.2.3.4", "port": 8388,
             "cipher": "aes-128-gcm", "password": "x"}]}),
        encoding="utf-8",
    )
    first = engine.publish_client_clash_config(fetch_remote=False)
    assert first["published"] is True
    last_path = temp_clash_root / "airports" / "mango-clash.yaml"
    before = last_path.read_text(encoding="utf-8")
    digest = first["sha256"]

    def noop_reconcile(**kwargs):
        return {}

    monkeypatch.setattr(engine, "reconcile_merged", noop_reconcile)
    monkeypatch.setattr(engine, "_client_export_inputs_fingerprint", lambda: "force-rerender")
    merged_path = temp_clash_root / "airports" / "airport-merged-sub.yaml"
    merged_path.write_text("proxies: [not: [ valid", encoding="utf-8")
    second = engine.publish_client_clash_config(fetch_remote=False)
    assert second["published"] is False
    assert second["served_last_good"] is True
    assert second["sha256"] == digest
    assert last_path.read_text(encoding="utf-8") == before


def test_validate_rejects_proxy_name_colliding_with_group():
    text = _minimal_client_yaml(
        extra_proxies=[
            {
                "name": "PROXY",
                "type": "ss",
                "server": "1.2.3.4",
                "port": 1,
                "cipher": "aes-128-gcm",
                "password": "x",
            }
        ]
    )
    errors = sm.validate_client_clash_yaml(text)
    assert any("PROXY" in e and "collid" in e.lower() for e in errors)


def test_validate_rejects_duplicate_group_names():
    doc = yaml.safe_load(_minimal_client_yaml())
    doc["proxy-groups"].append({"name": "AUTO", "type": "select", "proxies": ["DIRECT"]})
    errors = sm.validate_client_clash_yaml(yaml.safe_dump(doc, allow_unicode=True))
    assert any("duplicate group" in e for e in errors)


def test_publish_corrupt_last_good_is_not_served(temp_clash_root, monkeypatch):
    engine = SubscriptionEngine(root=temp_clash_root)
    (temp_clash_root / "airports").mkdir(parents=True, exist_ok=True)
    (temp_clash_root / "airports" / "mango-clash.yaml").write_text(
        "this is not clash yaml\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        engine,
        "render_client_clash_config",
        lambda fetch_remote=False: "proxies: []\nproxy-groups: []\n",
    )
    with pytest.raises(sm.ClientExportInvalid):
        engine.publish_client_clash_config(fetch_remote=False)
    assert (temp_clash_root / "airports" / "mango-clash.yaml").read_text() == "this is not clash yaml\n"


def test_publish_replaces_corrupt_last_good_with_valid_render(temp_clash_root):
    engine = SubscriptionEngine(root=temp_clash_root)
    (temp_clash_root / "airports").mkdir(parents=True, exist_ok=True)
    (temp_clash_root / "airports" / "mango-clash.yaml").write_text("corrupt\n", encoding="utf-8")
    (temp_clash_root / "airports" / "local-nodes.yaml").write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {
                        "name": "Keep-Direct",
                        "type": "ss",
                        "server": "1.2.3.4",
                        "port": 8388,
                        "cipher": "aes-128-gcm",
                        "password": "x",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    res = engine.publish_client_clash_config(fetch_remote=False)
    assert res["published"] is True
    assert res["served_last_good"] is False
    assert "Keep-Direct" in res["yaml"]
    assert "corrupt" not in (temp_clash_root / "airports" / "mango-clash.yaml").read_text()


def test_validate_rejects_unknown_rule_outbound():
    doc = yaml.safe_load(_minimal_client_yaml())
    doc["rules"] = ["MATCH,Ghost-Outbound"]
    errors = sm.validate_client_clash_yaml(yaml.safe_dump(doc, allow_unicode=True))
    assert any("Ghost-Outbound" in e for e in errors)


def test_publish_skips_render_when_sources_unchanged(temp_clash_root, monkeypatch):
    engine = SubscriptionEngine(root=temp_clash_root)
    (temp_clash_root / "airports").mkdir(parents=True, exist_ok=True)
    (temp_clash_root / "airports" / "local-nodes.yaml").write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {
                        "name": "Keep-Direct",
                        "type": "ss",
                        "server": "1.2.3.4",
                        "port": 8388,
                        "cipher": "aes-128-gcm",
                        "password": "x",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    renders = []
    original = engine.render_client_clash_config

    def counted(fetch_remote=False):
        renders.append(fetch_remote)
        return original(fetch_remote=fetch_remote)

    monkeypatch.setattr(engine, "render_client_clash_config", counted)
    first = engine.publish_client_clash_config(fetch_remote=False)
    assert first["published"] is True
    assert len(renders) == 1
    second = engine.publish_client_clash_config(fetch_remote=False)
    assert second["published"] is False
    assert second["sha256"] == first["sha256"]
    assert len(renders) == 1


def test_publish_skips_kernel_when_content_unchanged(temp_clash_root, monkeypatch):
    engine = SubscriptionEngine(root=temp_clash_root)
    (temp_clash_root / "airports").mkdir(parents=True, exist_ok=True)
    (temp_clash_root / "airports" / "local-nodes.yaml").write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {
                        "name": "Keep-Direct",
                        "type": "ss",
                        "server": "1.2.3.4",
                        "port": 8388,
                        "cipher": "aes-128-gcm",
                        "password": "x",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    dummy = temp_clash_root / "mihomo"
    dummy.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    dummy.chmod(0o755)
    calls = []

    def fake_kernel(text, kernel_bin, workdir):
        calls.append(str(kernel_bin))
        return None

    monkeypatch.setattr(sm, "_kernel_test_client_yaml", fake_kernel)
    first = engine.publish_client_clash_config(fetch_remote=False)
    assert first["published"] is True
    assert len(calls) == 1
    second = engine.publish_client_clash_config(fetch_remote=False)
    assert second["published"] is False
    assert second["served_last_good"] is False
    assert second["sha256"] == first["sha256"]
    assert len(calls) == 1




# ---------------------------------------------------------------------------
# 2026-11-03: self-built naming (tag + region flag) / denylist consistency
# ---------------------------------------------------------------------------

SELF_TAG = sm.SELF_TAG
TAGGED_HK = "[自建] 🇭🇰TUIC-Azure"
TAGGED_US = "[自建] 🇺🇸TUIC-googlevps"


def test_strip_self_tag_only_strips_self_built_flags():
    assert sm.strip_self_tag(TAGGED_HK) == "TUIC-Azure"
    assert sm.strip_self_tag("[自建] TUIC-Azure") == "TUIC-Azure"
    assert sm.strip_self_tag("TUIC-Azure") == "TUIC-Azure"
    # airport names keep their own leading flag
    assert sm.strip_self_tag("🇸🇬【亚洲】新加坡03丨直连") == "🇸🇬【亚洲】新加坡03丨直连"


def test_is_denylisted_accepts_every_spelling():
    assert sm.is_denylisted(TAGGED_HK, {"TUIC-Azure"})
    assert sm.is_denylisted(TAGGED_HK, {TAGGED_HK})
    assert sm.is_denylisted(TAGGED_HK, {"[自建] TUIC-Azure"})
    assert not sm.is_denylisted(TAGGED_HK, {"AnyTLS-Azure"})
    assert not sm.is_denylisted(None, {"TUIC-Azure"})


def test_save_disabled_nodes_records_self_built_bare_name(temp_clash_root):
    engine = SubscriptionEngine(root=temp_clash_root)
    sm.save_disabled_nodes({TAGGED_US}, engine.disabled_file)

    saved = engine.disabled_file.read_text(encoding="utf-8")
    assert "TUIC-googlevps" in saved
    assert TAGGED_US not in saved
    # and it round-trips: the tagged node is recognised as denylisted
    assert sm.is_denylisted(TAGGED_US, sm.load_disabled_nodes(engine.disabled_file))


def test_reconcile_prunes_denylisted_tagged_proxy(temp_clash_root):
    """A bare denylist entry must also prune the flagged, tagged live node."""
    cfg = temp_clash_root / "config.yaml"
    cfg.write_text(yaml.safe_dump({
        "proxies": [
            {"name": TAGGED_HK, "server": "104.208.65.233", "port": 47931, "type": "tuic"},
            {"name": "🇸🇬【亚洲】新加坡03丨直连", "server": "1.2.3.4", "port": 443, "type": "trojan"},
        ],
        "proxy-groups": [
            {"name": sm.SUB_GROUP_NAME, "type": "select", "proxies": ["DIRECT"]},
            {"name": "PROXY", "type": "select", "proxies": [TAGGED_HK, "🇸🇬【亚洲】新加坡03丨直连", "DIRECT"]},
        ],
        "rules": ["MATCH,PROXY"],
    }, allow_unicode=True), encoding="utf-8")

    changed = sm.reconcile_target_config(cfg, None, disabled_nodes={"TUIC-Azure"})
    assert changed is True
    out = yaml.safe_load(cfg.read_text(encoding="utf-8"))
    names = [p["name"] for p in out["proxies"]]
    assert names == ["🇸🇬【亚洲】新加坡03丨直连"]
    assert TAGGED_HK not in out["proxy-groups"][1]["proxies"]


def test_reconcile_does_not_strip_flag_from_airport_names(temp_clash_root):
    """An airport node flagged 🇸🇬 must not be pruned by a bare denylist entry."""
    cfg = temp_clash_root / "config.yaml"
    airport = "🇸🇬【亚洲】新加坡03丨直连"
    cfg.write_text(yaml.safe_dump({
        "proxies": [{"name": airport, "server": "1.2.3.4", "port": 443, "type": "trojan"}],
        "proxy-groups": [
            {"name": sm.SUB_GROUP_NAME, "type": "select", "proxies": ["DIRECT"]},
            {"name": "PROXY", "type": "select", "proxies": [airport, "DIRECT"]},
        ],
        "rules": ["MATCH,PROXY"],
    }, allow_unicode=True), encoding="utf-8")

    sm.reconcile_target_config(cfg, None, disabled_nodes={"【亚洲】新加坡03丨直连"})
    out = yaml.safe_load(cfg.read_text(encoding="utf-8"))
    assert airport in [p["name"] for p in out["proxies"]]


def test_prune_local_node_file_never_drops_self_built(temp_clash_root, monkeypatch):
    """A dead self-built node is reported, but stays in the pool source of truth."""
    engine = SubscriptionEngine(root=temp_clash_root)
    pool_dir = temp_clash_root / "airports"
    pool_dir.mkdir(parents=True, exist_ok=True)
    airport = "🇸🇬【亚洲】新加坡03丨直连"
    pool_dir.joinpath("local-nodes.yaml").write_text(yaml.safe_dump({
        "proxies": [
            {"name": TAGGED_HK, "server": "104.208.65.233", "port": 47931, "type": "tuic"},
            {"name": airport, "server": "1.2.3.4", "port": 443, "type": "trojan"},
        ],
        "groups": {"vps-import": [TAGGED_HK, airport]},
    }, allow_unicode=True), encoding="utf-8")

    # both endpoints are "dead"
    monkeypatch.setattr(
        sm, "probe_nodes",
        lambda nodes, **kw: ([], [dict(n) for n in nodes]),
    )

    result = engine.prune_local_node_file()
    assert result["success"] is True
    # the self-built node is reported, not dropped
    assert TAGGED_HK in result["dead_self_built"]
    assert TAGGED_HK not in result["newly_dead"]
    kept = [p["name"] for p in sm.load_local_nodes_file(pool_dir / "local-nodes.yaml")]
    assert TAGGED_HK in kept          # source of truth intact
    assert airport not in kept        # airport node still pruned
    disabled = sm.load_disabled_nodes(engine.disabled_file)
    assert TAGGED_HK not in disabled
