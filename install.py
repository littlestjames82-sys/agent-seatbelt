#!/usr/bin/env python3
"""Install Agent Seatbelt's hook into Claude Code's settings.json.

For users who don't use the plugin system. Merges safely:
- existing settings are preserved; a .bak backup is written on change;
- re-running is a no-op if the hook is already installed (idempotent);
- --dry-run prints what would change and writes nothing.

--harden (S6) additionally writes matching native permissions
deny/ask entries for the worst locked patterns. Native permissions
beat hook decisions in Claude Code, so this is defense in depth for
the day the hook itself fails to load. Existing entries are never
removed.

Usage:
  python3 install.py [--settings PATH] [--dry-run] [--harden]
                     [--uninstall]
"""

import argparse
import copy
import json
import sys
import time
from pathlib import Path

HOOK_FILE = Path(__file__).resolve().parent / "hooks" / "seatbelt_hook.py"
MATCHER = "Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|Read"
MCP_MATCHER = "^mcp__"

HARDEN_DENY = [
    "Bash(rm -rf *)", "Bash(rm -fr *)", "Bash(git push --force *)",
    "Bash(git push -f *)", "Bash(terraform destroy*)",
    "Bash(*DROP TABLE*)", "Bash(*drop table*)",
    "Bash(curl * | bash*)", "Bash(curl * | sh*)",
    "Bash(wget * | bash*)", "Bash(wget * | sh*)",
    "Bash(sudo rm *)", "Bash(mkfs*)",
]
HARDEN_ASK = [
    "Bash(git push *)", "Bash(npm publish*)", "Bash(sudo *)",
    "Bash(cat .env*)", "Bash(cat */.env*)", "Bash(rm *)",
    "Bash(vercel deploy*)", "Bash(netlify deploy*)",
    "Bash(kubectl delete *)", "Bash(crontab *)",
]


def _hook_entry(matcher):
    return {"matcher": matcher,
            "hooks": [{"type": "command",
                       "command": 'python3 "%s"' % HOOK_FILE,
                       "timeout": 5}]}


def _has_seatbelt(entries):
    return any("seatbelt_hook" in json.dumps(e) for e in entries or [])


def merge(settings, harden=False, uninstall=False):
    settings = copy.deepcopy(settings or {})
    hooks = settings.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])
    start = hooks.setdefault("SessionStart", [])
    if uninstall:
        hooks["PreToolUse"] = [e for e in pre if "seatbelt_hook" not in json.dumps(e)]
        hooks["SessionStart"] = [e for e in start if "seatbelt_hook" not in json.dumps(e)]
        return settings
    if not _has_seatbelt(pre):
        pre.append(_hook_entry(MATCHER))
        pre.append(_hook_entry(MCP_MATCHER))
    if not _has_seatbelt(start):
        start.append({"hooks": [{"type": "command",
                                 "command": 'python3 "%s"' % HOOK_FILE,
                                 "timeout": 5}]})
    if harden:
        perms = settings.setdefault("permissions", {})
        for key, wanted in (("deny", HARDEN_DENY), ("ask", HARDEN_ASK)):
            current = perms.setdefault(key, [])
            for item in wanted:
                if item not in current:
                    current.append(item)
    return settings


def _diff_lines(before, after):
    lines = []
    b = json.dumps(before, sort_keys=True)
    for entry in after.get("hooks", {}).get("PreToolUse", []):
        if "seatbelt_hook" in json.dumps(entry) and json.dumps(entry, sort_keys=True) not in b:
            lines.append("+ hooks.PreToolUse: %s" % json.dumps(entry))
    for entry in after.get("hooks", {}).get("SessionStart", []):
        if "seatbelt_hook" in json.dumps(entry) and json.dumps(entry, sort_keys=True) not in b:
            lines.append("+ hooks.SessionStart: %s" % json.dumps(entry))
    for key in ("deny", "ask"):
        before_set = set((before.get("permissions") or {}).get(key, []))
        for item in (after.get("permissions") or {}).get(key, []):
            if item not in before_set:
                lines.append("+ permissions.%s: %s" % (key, item))
    return lines


def _canary_registry_path():
    return Path.home() / ".claude" / "seatbelt" / "canaries.json"


def _plant_canaries(args):
    """Z1: plant decoy credential files; registry stores hashes only."""
    import hashlib
    import secrets as _secrets
    registry_path = _canary_registry_path()
    existing = []
    if registry_path.is_file():
        try:
            existing = json.loads(
                registry_path.read_text(encoding="utf-8")).get("canaries", [])
        except Exception:
            existing = []
    if args.remove:
        removed = []
        for entry in existing:
            p = Path(entry.get("path", ""))
            try:
                if p.is_file():
                    p.unlink()
                    removed.append(str(p))
            except OSError:
                pass
        try:
            registry_path.unlink()
        except OSError:
            pass
        for r in removed:
            print("canary removed: %s" % r)
        print("canary registry cleared: %s" % registry_path)
        return 0
    home = Path.home()
    targets = [
        ("aws-decoy", home / ".aws" / "credentials.seatbelt-canary",
         "[seatbelt-decoy]\naws_access_key_id = AKIA{KEY}\n"
         "aws_secret_access_key = {TOKEN}\n"),
        ("kube-decoy", home / ".kube" / "config.seatbelt-canary",
         "apiVersion: v1\nkind: Config\nusers:\n- name: decoy\n  user:\n"
         "    token: {TOKEN}\n"),
    ]
    project_env = Path.cwd() / ".env.canary"
    in_git = (Path.cwd() / ".git").exists()
    plant_project = True
    if in_git and not args.yes:
        if sys.stdin.isatty():
            answer = input("Plant a project canary at %s? It will be an "
                           "untracked file in a git repo. [y/N] "
                           % project_env)
            plant_project = answer.strip().lower().startswith("y")
        else:
            plant_project = False
            print("note: skipping project canary %s (inside a git repo; "
                  "re-run with --yes to plant it)" % project_env)
    if plant_project:
        targets.append(("project-env-decoy", project_env,
                        "API_KEY={TOKEN}\nSERVICE_SECRET={TOKEN}\n"))
    entries = list(existing)
    planted = []
    for cid, path, template in targets:
        token = "SBCT-" + _secrets.token_hex(16)
        key = _secrets.token_hex(8).upper()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(template.replace("{TOKEN}", token)
                        .replace("{KEY}", key), encoding="utf-8")
        entries.append({
            "id": cid, "path": str(path),
            "sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
            "planted": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
        planted.append(str(path))
        print("canary planted: %s" % path)
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(json.dumps(
        {"canaries": entries}, indent=2) + "\n", encoding="utf-8")
    print("registry (hashes only, token values are never stored): %s"
          % registry_path)
    print("Any read of a canary file, or any command carrying a canary "
          "value, is denied in every mode and logged as a canary-trip.")
    print("Remove them any time: python3 install.py --canaries --remove")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--settings", default=str(Path.home() / ".claude" / "settings.json"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--harden", action="store_true")
    ap.add_argument("--uninstall", action="store_true")
    ap.add_argument("--canaries", action="store_true",
                    help="plant decoy credential (canary) files")
    ap.add_argument("--remove", action="store_true",
                    help="with --canaries: remove planted canaries")
    ap.add_argument("--yes", action="store_true",
                    help="with --canaries: skip confirmations")
    args = ap.parse_args(argv)
    if args.canaries:
        return _plant_canaries(args)
    path = Path(args.settings)
    before = {}
    if path.is_file():
        try:
            before = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            sys.stderr.write("settings file is not valid JSON: %s\n" % exc)
            return 2
    after = merge(before, harden=args.harden, uninstall=args.uninstall)
    lines = _diff_lines(before, after)
    if args.uninstall and json.dumps(before, sort_keys=True) != json.dumps(after, sort_keys=True):
        lines = ["- seatbelt hook entries removed"]
    if not lines and not args.uninstall:
        print("Seatbelt is already installed in %s — nothing to change." % path)
        return 0
    for line in lines:
        print(line)
    if args.dry_run:
        print("(dry run — nothing written)")
        return 0
    if path.is_file():
        backup = path.with_suffix(path.suffix + ".bak")
        backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        print("backup written: %s" % backup)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(after, indent=2) + "\n", encoding="utf-8")
    print("installed into %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
