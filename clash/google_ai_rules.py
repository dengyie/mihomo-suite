"""Google AI endpoints routed to the 🎯Google group - the single source.

Consumed by both writers of Google AI routing:
- subscription-manager.py: client export (CLIENT_GOOGLE_RULES, ahead of the
  generic Google rules; client Script.js passes 🎯Google rules through).
- rules-reconciler.py: live server configs (config.yaml /
  config.mac-merged.yaml), as a managed block right after the user rules.
Edit only here; never hand-add these to rules/user-rules.yaml.

2026-11-27: Gemini / AI Studio / NotebookLM / Antigravity / Jules / Labs
(owner-supplied list). New gTLDs (.google/.goog/ai.studio/gemma.ai) plus
deepmind.com / withgoogle.com / google.dev are not covered by the generic
google.com/googleapis.com suffixes and used to fall to MATCH,PROXY. Entries
already covered by those suffixes stay listed on purpose (explicit list for
auditing, ordered before the generic Google rules).
"""
from typing import List

GOOGLE_AI_GROUP = '🎯Google'

GOOGLE_AI_DOMAINS = (
    'ai.google.dev',
    'alkalicore-pa.clients6.google.com',
    'alkalimakersuite-pa.clients6.google.com',
    'webchannel-alkalimakersuite-pa.clients6.google.com',
    'geminiweb-pa.clients.google.com',
    'geminiweb-pa.clients6.google.com',
    'appsgenaiserver-pa.clients.google.com',
    'appsgenaiserver-pa.clients6.google.com',
    'appsgenaiserver-pa.googleapis.com',
    'cloudaicompanion.googleapis.com',
    'cloudcode-pa.googleapis.com',
    'daily-cloudcode-pa.googleapis.com',
    'notebooklm-pa.googleapis.com',
    'notebooklm.googleapis.com',
    'antigravity-pa.googleapis.com',
    'antigravity.googleapis.com',
)
GOOGLE_AI_SUFFIXES = (
    'notebook.google',
    'deepmind.google',
    'gemma.ai',
    'antigravity-unleash.goog',
    'antigravity.google',
    'opal.google',
    'generativeai.google',
    'flow.google',
    'ai.studio',
    'labs.google',
    'jules.google',
    'gemini.google',
    'notebooklm.google',
    'deepmind.com',
    'notebook.google.com',
    'makersuite.google.com',
    'gemini.gstatic.com',
    'gemini.google.com',
    'notebooklm.google.com',
    'bard.google.com',
    'jules.google.com',
    'aistudio.google.com',
    'labs.google.com',
    'geller-pa.googleapis.com',
    'flow.google.com',
    'aisandbox-pa.googleapis.com',
    'aicode.googleapis.com',
    'aida.googleapis.com',
    'robinfrontend-pa.googleapis.com',
    'opal.google.com',
    'proactivebackend-pa.googleapis.com',
    'generativelanguage.googleapis.com',
    'stitch.withgoogle.com',
    'labstailwind.pa.googleapis.com',
)


def google_ai_rules(group: str = GOOGLE_AI_GROUP) -> List[str]:
    """Mihomo rule strings, DOMAIN entries first, then DOMAIN-SUFFIX."""
    return ([f'DOMAIN,{d},{group}' for d in GOOGLE_AI_DOMAINS]
            + [f'DOMAIN-SUFFIX,{d},{group}' for d in GOOGLE_AI_SUFFIXES])
