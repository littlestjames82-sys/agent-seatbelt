"""T9/V5: the hook must make no network calls — proven statically.

Parses hooks/seatbelt_hook.py with the stdlib AST and asserts the
import surface contains no networking modules and no socket/urllib
usage, including the Round 6 feed code paths (the Disaster Feed ships
inside releases; the hook never phones home). The hook's only
subprocess calls are local tools (git, the gated command's own
rehearsal twins).
"""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "hooks" / "seatbelt_hook.py"

BANNED_MODULES = {
    "socket", "urllib", "requests", "http.client", "http", "ftplib",
    "smtplib", "telnetlib", "asyncio", "ssl", "websockets", "httpx",
}


def test_no_network_imports():
    tree = ast.parse(HOOK.read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
                imported.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
            imported.add(node.module)
    offenders = imported & BANNED_MODULES
    assert offenders == set(), "network-capable imports present: %s" % offenders


def test_no_dynamic_network_calls():
    # Note: the hook's DETECTOR patterns legitimately contain strings
    # like "urllib.request.urlopen(" — they are regexes for spotting
    # network code in agent scripts, not calls. So this test checks
    # call-shaped usage in executable positions via the AST instead:
    # no attribute access on network modules anywhere.
    tree = ast.parse(HOOK.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            assert node.value.id not in ("socket", "urllib", "requests"), \
                "network attribute use: %s.%s" % (node.value.id, node.attr)
    src = HOOK.read_text()
    for needle in ("requests.get(", "requests.post(", "http.client.HTTPS",
                   "http.client.HTTPConnection"):
        assert needle not in src, needle


def test_import_surface_is_stdlib_only():
    tree = ast.parse(HOOK.read_text())
    import sys
    stdlib = getattr(sys, "stdlib_module_names", set())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    if stdlib:
        assert imported <= stdlib, imported - stdlib
