"""Unit tests for the new gateway endpoints: authentication, subscription management,
egress IP race diagnostics, and rule simulation.
"""
import importlib.util
import io
import json
import os
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest import mock
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_gateway():
    spec = importlib.util.spec_from_file_location(
        "gateway_under_test",
        REPO_ROOT / "zashboard" / "gateway.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _FakeRequestHarness:
    """Helper to simulate HTTP requests against Handler methods."""

    def __init__(self, gw, method='GET', path='/panel/api/subscriptions', body=None, auth_token=None):
        self.gw = gw
        self.handler = object.__new__(gw.Handler)
        self.handler.command = method
        self.handler.path = path
        self.handler.requestline = f"{method} {path} HTTP/1.1"

        headers = Message()
        if auth_token is not None:
            headers['Authorization'] = f"Bearer {auth_token}"
        if body:
            body_bytes = body.encode('utf-8') if isinstance(body, str) else body
            headers['Content-Length'] = str(len(body_bytes))
            self.handler.rfile = io.BytesIO(body_bytes)
        else:
            headers['Content-Length'] = '0'
            self.handler.rfile = io.BytesIO(b'')

        self.handler.headers = headers
        self.handler.wfile = io.BytesIO()

        # Capture response status and headers
        self.response_status = None
        self.response_headers = {}

        def _send_response(status, message=None):
            self.response_status = status

        def _send_header(k, v):
            self.response_headers[k] = v

        def _end_headers():
            pass

        self.handler.send_response = _send_response
        self.handler.send_header = _send_header
        self.handler.end_headers = _end_headers

    def get_json(self):
        output = self.handler.wfile.getvalue().decode('utf-8')
        if not output:
            return None
        return json.loads(output)


class GatewayEndpointsTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.tmpdir.name)
        self.clash_dir = self.test_dir / 'clash'
        self.clash_dir.mkdir(parents=True, exist_ok=True)

        self.orig_env = dict(os.environ)
        os.environ['CLASH_ROOT'] = str(self.clash_dir)
        os.environ['ZASHBOARD_DIST'] = str(self.test_dir / 'dist')

        self.password_file = self.test_dir / 'panel.password'
        self.password_file.write_text('secret-token-123')
        os.environ['PANEL_PASSWORD_FILE'] = str(self.password_file)

        # Copy subscription-manager.py and rules-reconciler.py into clash_dir
        (self.clash_dir / 'subscription-manager.py').write_text(
            (REPO_ROOT / 'clash' / 'subscription-manager.py').read_text()
        )
        (self.clash_dir / 'rules-reconciler.py').write_text(
            (REPO_ROOT / 'clash' / 'rules-reconciler.py').read_text()
        )
        # sibling dependency of subscription-manager.py (shared config lock)
        (self.clash_dir / 'clash_lock.py').write_text(
            (REPO_ROOT / 'clash' / 'clash_lock.py').read_text()
        )

        # Create basic config.yaml in clash_dir
        sample_config = {
            'dns': {
                'enable': True,
                'nameserver': ['223.5.5.5', '114.114.114.114'],
                'nameserver-policy': {
                    '+.openai.com': 'https://1.1.1.1/dns-query'
                }
            },
            'rules': [
                'DOMAIN-SUFFIX,openai.com,PROXY',
                'MATCH,DIRECT',
            ],
            'proxy-groups': [
                {'name': 'PROXY', 'type': 'select', 'proxies': ['DIRECT']},
            ]
        }
        (self.clash_dir / 'config.yaml').write_text(yaml.safe_dump(sample_config))

        self.gw = _load_gateway()
        self.gw.PANEL_PASSWORD_FILE = self.password_file
        self.gw.CLASH_ROOT = self.clash_dir
        self.gw.SUBSCRIPTION_MANAGER_PATH = self.clash_dir / 'subscription-manager.py'
        self.gw.RECONCILER_PATH = self.clash_dir / 'rules-reconciler.py'
        self.token = 'secret-token-123'

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.orig_env)
        self.tmpdir.cleanup()

    # -------------------------------------------------------------
    # Authentication Protection Tests for all new endpoints
    # -------------------------------------------------------------
    def test_unauthenticated_requests_are_rejected(self):
        endpoints = [
            ('GET', '/panel/api/subscriptions', None),
            ('POST', '/panel/api/subscriptions', '{"name": "test"}'),
            ('POST', '/panel/api/subscriptions/sub-1/update', '{}'),
            ('POST', '/panel/api/subscriptions/sub-1/toggle', '{}'),
            ('DELETE', '/panel/api/subscriptions/sub-1', None),
            ('POST', '/panel/api/subscriptions/import-nodes', '{"text": "ss://..."}'),
            ('GET', '/panel/api/diagnostics/egress-ip', None),
            ('POST', '/panel/api/rules/simulate', '{"domain": "openai.com"}'),
        ]
        for method, path, body in endpoints:
            harness = _FakeRequestHarness(self.gw, method=method, path=path, body=body, auth_token=None)
            self.gw.Handler._dispatch(harness.handler, method)
            self.assertEqual(harness.response_status, 401, f"Expected 401 for unauth {method} {path}")

    # -------------------------------------------------------------
    # Subscription Manager API Tests
    # -------------------------------------------------------------
    def test_subscriptions_crud_flow(self):
        # 1. GET empty subscriptions
        h1 = _FakeRequestHarness(self.gw, 'GET', '/panel/api/subscriptions', auth_token=self.token)
        self.gw.Handler._dispatch(h1.handler, 'GET')
        self.assertEqual(h1.response_status, 200)
        res1 = h1.get_json()
        self.assertEqual(res1['status'], 'ok')
        self.assertEqual(len(res1['data']['subscriptions']), 0)

        # 2. POST add subscription (raw content with SS node)
        ss_uri = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:8388#TestNode1"
        payload = {
            'name': 'MyAirPort',
            'type': 'raw',
            'raw_content': ss_uri,
            'probe': False,
            'inject_local': False,
        }
        h2 = _FakeRequestHarness(self.gw, 'POST', '/panel/api/subscriptions', body=json.dumps(payload), auth_token=self.token)
        self.gw.Handler._dispatch(h2.handler, 'POST')
        self.assertEqual(h2.response_status, 200)
        res2 = h2.get_json()
        self.assertEqual(res2['status'], 'ok')
        sub_id = res2['data']['subscription']['id']
        self.assertEqual(res2['data']['subscription']['node_count'], 1)

        # 3. GET verify subscription exists
        h3 = _FakeRequestHarness(self.gw, 'GET', '/panel/api/subscriptions', auth_token=self.token)
        self.gw.Handler._dispatch(h3.handler, 'GET')
        res3 = h3.get_json()
        self.assertEqual(len(res3['data']['subscriptions']), 1)
        self.assertEqual(res3['data']['subscriptions'][0]['id'], sub_id)

        # 4. POST toggle subscription
        h4 = _FakeRequestHarness(self.gw, 'POST', f'/panel/api/subscriptions/{sub_id}/toggle', auth_token=self.token)
        self.gw.Handler._dispatch(h4.handler, 'POST')
        self.assertEqual(h4.response_status, 200)
        res4 = h4.get_json()
        self.assertFalse(res4['data']['subscription']['enabled'])

        # 4b. PATCH toggle / update subscription
        h4b = _FakeRequestHarness(self.gw, 'PATCH', f'/panel/api/subscriptions/{sub_id}',
                                  body=json.dumps({'enabled': True}), auth_token=self.token)
        self.gw.Handler._dispatch(h4b.handler, 'PATCH')
        self.assertEqual(h4b.response_status, 200)
        res4b = h4b.get_json()
        self.assertTrue(res4b['data']['subscription']['enabled'])

        # 5. POST update subscription
        h5 = _FakeRequestHarness(self.gw, 'POST', f'/panel/api/subscriptions/{sub_id}/update',
                                 body=json.dumps({'name': 'UpdatedAirport', 'enabled': True}), auth_token=self.token)
        self.gw.Handler._dispatch(h5.handler, 'POST')
        self.assertEqual(h5.response_status, 200)
        res5 = h5.get_json()
        self.assertEqual(res5['data']['subscription']['name'], 'UpdatedAirport')
        self.assertTrue(res5['data']['subscription']['enabled'])

        # 6. DELETE subscription
        h6 = _FakeRequestHarness(self.gw, 'DELETE', f'/panel/api/subscriptions/{sub_id}', auth_token=self.token)
        self.gw.Handler._dispatch(h6.handler, 'DELETE')
        self.assertEqual(h6.response_status, 200)

        # 7. GET verify deleted
        h7 = _FakeRequestHarness(self.gw, 'GET', '/panel/api/subscriptions', auth_token=self.token)
        self.gw.Handler._dispatch(h7.handler, 'GET')
        res7 = h7.get_json()
        self.assertEqual(len(res7['data']['subscriptions']), 0)

    def test_subscriptions_import_nodes(self):
        raw_text = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:8388#ImportedNode1\nss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.5:8388#ImportedNode2"
        payload = {
            'name': 'BatchImport',
            'text': raw_text,
            'probe': False,
            'inject_local': False,
        }
        h = _FakeRequestHarness(self.gw, 'POST', '/panel/api/subscriptions/import-nodes', body=json.dumps(payload), auth_token=self.token)
        self.gw.Handler._dispatch(h.handler, 'POST')
        self.assertEqual(h.response_status, 200)
        res = h.get_json()
        self.assertEqual(res['status'], 'ok')
        self.assertEqual(res['data']['subscription']['node_count'], 2)

    # -------------------------------------------------------------
    # Egress IP Race Diagnostics API Tests
    # -------------------------------------------------------------
    def test_diagnostics_egress_ip(self):
        def fake_probe(src, timeout=3.5, use_proxy=True, proxy_port=7897):
            name = src.get('name')
            if name == 'cloudflare':
                return {
                    'ip': '198.51.100.1',
                    'country': 'US',
                    'city': 'San Jose',
                    'org': 'AS13335 Cloudflare, Inc.',
                }
            elif name == 'ipinfo.io':
                return {
                    'ip': '198.51.100.2',
                    'country': 'US',
                    'city': 'San Jose',
                    'org': 'ipinfo',
                }
            return None

        with mock.patch.object(self.gw, '_probe_egress_source', side_effect=fake_probe):
            h = _FakeRequestHarness(self.gw, 'GET', '/panel/api/diagnostics/egress-ip?proxy=true&proxy_port=7897', auth_token=self.token)
            self.gw.Handler._dispatch(h.handler, 'GET')
            self.assertEqual(h.response_status, 200)
            res = h.get_json()
            self.assertEqual(res['status'], 'ok')
            self.assertTrue(res['data']['success'])
            self.assertIsNotNone(res['data']['fastest'])
            self.assertIn(res['data']['fastest']['data']['ip'], ['198.51.100.1', '198.51.100.2'])
            self.assertTrue(len(res['data']['all_results']) >= 1)

    def test_diagnostics_all_failed(self):
        with mock.patch.object(self.gw, '_probe_egress_source', return_value=None):
            h = _FakeRequestHarness(self.gw, 'GET', '/panel/api/diagnostics/egress-ip', auth_token=self.token)
            self.gw.Handler._dispatch(h.handler, 'GET')
            self.assertEqual(h.response_status, 200)
            res = h.get_json()
            self.assertEqual(res['status'], 'ok')
            self.assertFalse(res['data']['success'])
            self.assertIn('failed', res['data']['message'])

    def test_query_token_authentication(self):
        h = _FakeRequestHarness(self.gw, 'GET', f'/panel/api/subscriptions?token={self.token}', auth_token=None)
        self.gw.Handler._dispatch(h.handler, 'GET')
        self.assertEqual(h.response_status, 200)

        h_bad = _FakeRequestHarness(self.gw, 'GET', '/panel/api/subscriptions?token=wrong_token', auth_token=None)
        self.gw.Handler._dispatch(h_bad.handler, 'GET')
        self.assertEqual(h_bad.response_status, 401)

    def test_client_clash_export_requires_token(self):
        h = _FakeRequestHarness(self.gw, 'GET', '/sub/clash', auth_token=None)
        self.gw.Handler._dispatch(h.handler, 'GET')
        self.assertEqual(h.response_status, 401)

        h_bad = _FakeRequestHarness(self.gw, 'GET', '/sub/clash?token=wrong', auth_token=None)
        self.gw.Handler._dispatch(h_bad.handler, 'GET')
        self.assertEqual(h_bad.response_status, 401)

    def test_client_clash_export_yaml(self):
        os.environ['CLIENT_SUB_TOKEN'] = 'client-export-token'
        sm = self.gw.get_sub_manager()
        engine = sm.SubscriptionEngine(root=self.clash_dir)
        imported = engine.import_raw_nodes(
            name='Export',
            raw_text='ss://YWVzLTEyOC1nY206cA==@9.9.9.9:8388#Export-Node',
        )
        self.assertTrue(imported.get('success'))

        h = _FakeRequestHarness(self.gw, 'GET', '/sub/clash?token=client-export-token', auth_token=None)
        self.gw.Handler._dispatch(h.handler, 'GET')
        self.assertEqual(h.response_status, 200)
        self.assertIn('yaml', h.response_headers.get('Content-Type', ''))
        disp = h.response_headers.get('Content-Disposition', '')
        self.assertEqual(disp, 'attachment; filename=mango-clash')
        self.assertNotIn('\\', disp)
        self.assertNotIn('"', disp)
        self.assertEqual(h.response_headers.get('profile-title'), 'mango-clash')
        body = h.handler.wfile.getvalue().decode('utf-8')
        doc = yaml.safe_load(body)
        self.assertEqual(doc['proxies'][0]['name'], '[Export] Export-Node')
        self.assertEqual(doc['dns']['enhanced-mode'], 'fake-ip')
        self.assertEqual(doc['rules'][-1], 'MATCH,PROXY')
        self.assertTrue(doc['tun']['enable'])
        self.assertEqual(doc['tun']['stack'], 'gvisor')
        self.assertTrue(h.response_headers.get('ETag', '').strip('"'))
        self.assertNotEqual(h.response_headers.get('X-Mango-Clash-Stale'), '1')
        last_good = self.clash_dir / 'airports' / 'mango-clash.yaml'
        self.assertTrue(last_good.exists())

        info = _FakeRequestHarness(self.gw, 'GET', '/panel/api/client-sub', auth_token=self.token)
        self.gw.Handler._dispatch(info.handler, 'GET')
        self.assertEqual(info.response_status, 200)
        info_json = info.get_json()
        self.assertEqual(info_json['data']['token'], 'client-export-token')
        self.assertEqual(info_json['data']['path'], '/sub/clash')

        unauth_info = _FakeRequestHarness(self.gw, 'GET', '/panel/api/client-sub', auth_token=None)
        self.gw.Handler._dispatch(unauth_info.handler, 'GET')
        self.assertEqual(unauth_info.response_status, 401)

    def test_client_clash_export_keeps_last_good_on_invalid_render(self):
        os.environ['CLIENT_SUB_TOKEN'] = 'client-export-token'
        sm = self.gw.get_sub_manager()
        engine = sm.SubscriptionEngine(root=self.clash_dir)
        imported = engine.import_raw_nodes(
            name='Export',
            raw_text='ss://YWVzLTEyOC1nY206cA==@9.9.9.9:8388#Export-Node',
        )
        self.assertTrue(imported.get('success'))

        h1 = _FakeRequestHarness(self.gw, 'GET', '/sub/clash?token=client-export-token', auth_token=None)
        self.gw.Handler._dispatch(h1.handler, 'GET')
        self.assertEqual(h1.response_status, 200)
        good_body = h1.handler.wfile.getvalue()
        good_etag = h1.response_headers.get('ETag')
        last_good = (self.clash_dir / 'airports' / 'mango-clash.yaml').read_bytes()

        def broken_render(self, fetch_remote=False):
            return (
                "proxies:\n"
                "  - name: ZooProxy-HK\n"
                "    type: http\n"
                "    server: 127.0.0.1\n"
                "    port: 1\n"
                "    dialer-proxy: AnyTLS-googlevps\n"
                "proxy-groups:\n"
                "  - name: PROXY\n"
                "    type: select\n"
                "    proxies: [ZooProxy-HK, DIRECT]\n"
            )

        with mock.patch.object(sm.SubscriptionEngine, 'render_client_clash_config', broken_render), \
                mock.patch.object(
                    sm.SubscriptionEngine,
                    '_client_export_inputs_fingerprint',
                    return_value='force-rerender',
                ):
            h2 = _FakeRequestHarness(self.gw, 'GET', '/sub/clash?token=client-export-token', auth_token=None)
            self.gw.Handler._dispatch(h2.handler, 'GET')
        self.assertEqual(h2.response_status, 200)
        self.assertEqual(h2.handler.wfile.getvalue(), good_body)
        self.assertEqual(h2.response_headers.get('ETag'), good_etag)
        self.assertEqual(h2.response_headers.get('X-Mango-Clash-Stale'), '1')
        self.assertEqual((self.clash_dir / 'airports' / 'mango-clash.yaml').read_bytes(), last_good)

        h3 = _FakeRequestHarness(self.gw, 'GET', '/sub/clash?token=client-export-token', auth_token=None)
        h3.handler.headers['If-None-Match'] = good_etag
        self.gw.Handler._dispatch(h3.handler, 'GET')
        self.assertEqual(h3.response_status, 304)
        self.assertEqual(h3.handler.wfile.getvalue(), b'')
        self.assertEqual(h3.response_headers.get('ETag'), good_etag)
        self.assertNotEqual(h3.response_headers.get('X-Mango-Clash-Stale'), '1')

        h4 = _FakeRequestHarness(self.gw, 'GET', '/sub/clash?token=client-export-token', auth_token=None)
        h4.handler.headers['If-None-Match'] = f'W/{good_etag}'
        self.gw.Handler._dispatch(h4.handler, 'GET')
        self.assertEqual(h4.response_status, 304)
        self.assertEqual(h4.handler.wfile.getvalue(), b'')
        self.assertEqual(h4.response_headers.get('ETag'), good_etag)

    # -------------------------------------------------------------
    # Rule Simulation API Tests
    # -------------------------------------------------------------
    def test_rules_simulate_api(self):
        payload = {'domain': 'api.openai.com'}
        h = _FakeRequestHarness(self.gw, 'POST', '/panel/api/rules/simulate', body=json.dumps(payload), auth_token=self.token)
        self.gw.Handler._dispatch(h.handler, 'POST')
        self.assertEqual(h.response_status, 200)
        res = h.get_json()
        self.assertEqual(res['status'], 'ok')
        self.assertTrue(res['data']['success'])
        self.assertEqual(res['data']['matched_rule']['type'], 'DOMAIN-SUFFIX')
        self.assertEqual(res['data']['matched_rule']['payload'], 'openai.com')
        self.assertEqual(res['data']['matched_rule']['target'], 'PROXY')
        self.assertIn('https://1.1.1.1/dns-query', res['data']['dns']['nameservers'])

    def test_simulate_rejects_config_path_escape(self):
        payload = {'domain': 'example.com', 'config_path': '/etc/passwd'}
        h = _FakeRequestHarness(self.gw, 'POST', '/panel/api/rules/simulate', body=json.dumps(payload), auth_token=self.token)
        self.gw.Handler._dispatch(h.handler, 'POST')
        self.assertEqual(h.response_status, 400)
        self.assertIn('CLASH_ROOT', h.get_json()['error'])

    def test_import_nodes_defaults_to_skip_merge(self):
        ss = 'ss://YWVzLTEyOC1nY206cA==@9.9.9.9:8388#Skip-HTTP'
        h = _FakeRequestHarness(
            self.gw,
            'POST',
            '/panel/api/subscriptions/import-nodes',
            body=json.dumps({'name': 'PanelPaste', 'text': ss, 'probe': False}),
            auth_token=self.token,
        )
        self.gw.Handler._dispatch(h.handler, 'POST')
        self.assertEqual(h.response_status, 200)
        sm = self.gw.get_sub_manager()
        engine = sm.SubscriptionEngine(root=self.clash_dir)
        listed = engine.list_subscriptions()
        self.assertTrue(listed[0]['skip_merge'])
        merged_path = self.clash_dir / 'airports' / 'airport-merged-sub.yaml'
        merged = yaml.safe_load(merged_path.read_text()) if merged_path.exists() else {}
        names = [p['name'] for p in (merged.get('proxies') or [])]
        self.assertEqual(names, [])

    def test_http_add_subscription_defaults_to_skip_merge(self):
        ss = 'ss://YWVzLTEyOC1nY206cA==@9.9.9.9:8388#HttpAdd'
        h = _FakeRequestHarness(
            self.gw,
            'POST',
            '/panel/api/subscriptions',
            body=json.dumps({'name': 'HttpAdd', 'type': 'raw', 'raw_content': ss, 'probe': False, 'inject_local': False}),
            auth_token=self.token,
        )
        self.gw.Handler._dispatch(h.handler, 'POST')
        self.assertEqual(h.response_status, 200)
        sm = self.gw.get_sub_manager()
        engine = sm.SubscriptionEngine(root=self.clash_dir)
        listed = engine.list_subscriptions()
        self.assertTrue(listed[0]['skip_merge'])

    def test_http_import_injects_alive_into_local_nodes(self):
        ss = 'ss://YWVzLTEyOC1nY206cA==@9.9.9.9:8388#Inject-HTTP'
        sm_mod = self.gw.get_sub_manager()

        def fake_probe(nodes, timeout=1.5, max_workers=8, keep_ssrf=False):
            return list(nodes), []

        with mock.patch.object(sm_mod, 'probe_nodes', side_effect=fake_probe):
            h = _FakeRequestHarness(
                self.gw,
                'POST',
                '/panel/api/subscriptions/import-nodes',
                body=json.dumps({'name': 'InjectHTTP', 'text': ss}),
                auth_token=self.token,
            )
            self.gw.Handler._dispatch(h.handler, 'POST')
        self.assertEqual(h.response_status, 200)
        body = h.get_json()
        self.assertEqual(body['data']['inject']['injected'], 1)
        local = yaml.safe_load((self.clash_dir / 'airports' / 'local-nodes.yaml').read_text())
        names = [p['name'] for p in local['proxies']]
        self.assertIn('[InjectHTTP] Inject-HTTP', names)

    def test_http_import_skip_merge_without_injection_stays_out_of_vps_import(self):
        # skip_merge=True + inject_local=False (pure isolation, no injection)
        # must NOT be coerced into vps-import — that group feeds the live VPS
        # config and would leak an isolated subscription into production egress.
        ss = 'ss://YWVzLTEyOC1nY206cA==@10.20.30.40:8388#Isolated'
        h = _FakeRequestHarness(
            self.gw,
            'POST',
            '/panel/api/subscriptions/import-nodes',
            body=json.dumps({'name': 'IsolatedSub', 'text': ss, 'probe': False, 'inject_local': False, 'skip_merge': True}),
            auth_token=self.token,
        )
        self.gw.Handler._dispatch(h.handler, 'POST')
        self.assertEqual(h.response_status, 200)
        sm_mod = self.gw.get_sub_manager()
        engine = sm_mod.SubscriptionEngine(root=self.clash_dir)
        sub = next(s for s in engine.list_subscriptions() if s['name'] == 'IsolatedSub')
        self.assertNotIn(sub.get('target_group'), ('vps-import',))
        local_path = self.clash_dir / 'airports' / 'local-nodes.yaml'
        if local_path.exists():
            local = yaml.safe_load(local_path.read_text())
            vps = local.get('groups', {}).get('vps-import', [])
            self.assertEqual(vps, [])
            self.assertNotIn('[IsolatedSub] Isolated', [p['name'] for p in local.get('proxies', [])])
        merged_path = self.clash_dir / 'airports' / 'airport-merged-sub.yaml'
        merged = yaml.safe_load(merged_path.read_text()) if merged_path.exists() else {}
        self.assertEqual([p['name'] for p in (merged.get('proxies') or [])], [])

    def test_http_delete_subscription_retracts_injected_nodes(self):
        ss = 'ss://YWVzLTEyOC1nY206cA==@8.8.4.4:8388#DelRetract'
        sm_mod = self.gw.get_sub_manager()

        def fake_probe(nodes, timeout=1.5, max_workers=8, keep_ssrf=False):
            return list(nodes), []

        with mock.patch.object(sm_mod, 'probe_nodes', side_effect=fake_probe):
            h = _FakeRequestHarness(
                self.gw,
                'POST',
                '/panel/api/subscriptions/import-nodes',
                body=json.dumps({'name': 'DelMe', 'text': ss}),
                auth_token=self.token,
            )
            self.gw.Handler._dispatch(h.handler, 'POST')
        self.assertEqual(h.response_status, 200)
        engine = sm_mod.SubscriptionEngine(root=self.clash_dir)
        sub = next(s for s in engine.list_subscriptions() if s['name'] == 'DelMe')
        local_before = yaml.safe_load((self.clash_dir / 'airports' / 'local-nodes.yaml').read_text())
        self.assertIn('[DelMe] DelRetract', [p['name'] for p in local_before['proxies']])

        h2 = _FakeRequestHarness(
            self.gw,
            'DELETE',
            f'/panel/api/subscriptions/{sub["id"]}',
            auth_token=self.token,
        )
        self.gw.Handler._dispatch(h2.handler, 'DELETE')
        self.assertEqual(h2.response_status, 200)
        local_after = yaml.safe_load((self.clash_dir / 'airports' / 'local-nodes.yaml').read_text())
        names_after = [p['name'] for p in local_after['proxies']]
        self.assertNotIn('[DelMe] DelRetract', names_after)
        self.assertEqual(local_after['groups'].get('vps-import', []), [])

    def test_prune_get_is_rejected(self):
        h = _FakeRequestHarness(self.gw, 'GET', '/panel/api/diagnostics/prune-dead-nodes', auth_token=self.token)
        self.gw.Handler._dispatch(h.handler, 'GET')
        self.assertEqual(h.response_status, 405)

    def test_mihomo_proxy_rejects_unknown_path(self):
        h = _FakeRequestHarness(self.gw, 'GET', '/panel/api/debug/pprof', auth_token=self.token)
        self.gw.Handler._dispatch(h.handler, 'GET')
        self.assertEqual(h.response_status, 403)

    def test_delay_url_must_be_allowlisted(self):
        h = _FakeRequestHarness(
            self.gw,
            'GET',
            '/panel/api/proxies/Foo/delay?url=http://169.254.169.254/',
            auth_token=self.token,
        )
        self.gw.Handler._dispatch(h.handler, 'GET')
        self.assertEqual(h.response_status, 403)

    def test_add_remote_fetch_failure_returns_502(self):
        sm_mod = self.gw.get_sub_manager()
        with mock.patch.object(
            sm_mod.SubscriptionEngine,
            'fetch_url',
            side_effect=ValueError('HTTP 500'),
        ):
            h = _FakeRequestHarness(
                self.gw,
                'POST',
                '/panel/api/subscriptions',
                body=json.dumps({'name': 'Down', 'url': 'https://sub.example.com/clash'}),
                auth_token=self.token,
            )
            self.gw.Handler._dispatch(h.handler, 'POST')
        self.assertEqual(h.response_status, 502)
        body = h.get_json()
        self.assertEqual(body['status'], 'error')
        self.assertTrue(str(body['error']).startswith('Fetch failed'))

    def test_index_html_does_not_contain_panel_password(self):
        html = (REPO_ROOT / 'zashboard' / 'dist' / 'index.html').read_text()
        self.assertNotIn('__PANEL_PASSWORD__', html)
        self.assertNotIn(self.token, html)
        gw_src = (REPO_ROOT / 'zashboard' / 'gateway.py').read_text()
        self.assertNotIn("data.replace(b'__PANEL_PASSWORD__'", gw_src)


if __name__ == '__main__':
    unittest.main()
