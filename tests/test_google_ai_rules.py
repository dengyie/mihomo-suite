"""Google AI routing has ONE source (clash/google_ai_rules.py) feeding both
writers: the client export (subscription-manager CLIENT_GOOGLE_RULES) and
the live server configs (rules-reconciler managed block)."""
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'clash'))


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'clash' / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gar = _load('google_ai_rules', 'google_ai_rules.py')
rr = _load('rules_reconciler_under_test', 'rules-reconciler.py')
sm = _load('subscription_manager_under_test', 'subscription-manager.py')

G = gar.GOOGLE_AI_GROUP
MANAGED = gar.google_ai_rules(G)


def _cfg(groups=(G, 'PROXY'), rules=('MATCH,PROXY',)):
    return {'proxy-groups': [{'name': g, 'type': 'select', 'proxies': ['DIRECT']} for g in groups],
            'rules': list(rules)}


class SingleSourceTests(unittest.TestCase):
    def test_client_export_uses_shared_list_first(self):
        self.assertEqual(sm.GOOGLE_GROUP, G)
        self.assertEqual(sm.CLIENT_GOOGLE_RULES[:len(MANAGED)], MANAGED)

    def test_list_has_no_duplicates_and_expected_shape(self):
        self.assertEqual(len(MANAGED), len(set(MANAGED)))
        self.assertIn('DOMAIN,ai.google.dev,' + G, MANAGED)
        self.assertIn('DOMAIN-SUFFIX,gemini.google,' + G, MANAGED)


class ReconcilerManagedBlockTests(unittest.TestCase):
    def test_managed_block_follows_user_rules(self):
        user = [{'id': 'u1', 'type': 'DOMAIN-SUFFIX', 'payload': 'x.example', 'target': 'DIRECT'}]
        cfg, injected = rr.merge_rules_into_config(_cfg(), user, [])
        self.assertEqual(cfg['rules'], ['DOMAIN-SUFFIX,x.example,DIRECT'] + MANAGED + ['MATCH,PROXY'])
        self.assertEqual(injected, cfg['rules'][:-1])

    def test_user_rule_already_present_is_not_duplicated(self):
        dup = MANAGED[-1].split(',')
        user = [{'id': 'u1', 'type': dup[0], 'payload': dup[1], 'target': dup[2]}]
        cfg, _ = rr.merge_rules_into_config(_cfg(), user, [])
        self.assertEqual(cfg['rules'].count(MANAGED[-1]), 1)
        self.assertEqual(cfg['rules'][0], MANAGED[-1])

    def test_reconcile_is_idempotent_via_tracker(self):
        cfg, injected = rr.merge_rules_into_config(_cfg(), [], [])
        again, injected2 = rr.merge_rules_into_config(dict(cfg), [], injected)
        self.assertEqual(again['rules'], MANAGED + ['MATCH,PROXY'])
        self.assertEqual(injected2, injected)

    def test_hand_entered_rows_removed_keeps_config_identical(self):
        # migration: old user-rules carried the list by hand; dropping those
        # rows must leave the rendered rules unchanged
        hand = [dict(zip(('type', 'payload', 'target'), r.split(',')), id=f'h{i}')
                for i, r in enumerate(MANAGED)]
        old, old_inj = rr.merge_rules_into_config(_cfg(), hand, [])
        new, _ = rr.merge_rules_into_config(dict(old), [], old_inj)
        self.assertEqual(new['rules'], old['rules'])

    def test_skipped_without_google_group(self):
        cfg, injected = rr.merge_rules_into_config(_cfg(groups=('PROXY',)), [], [])
        self.assertEqual(cfg['rules'], ['MATCH,PROXY'])
        self.assertEqual(injected, [])


if __name__ == '__main__':
    unittest.main()
