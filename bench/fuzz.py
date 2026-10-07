#!/usr/bin/env python3
"""Seatbelt fuzz — GuardFall-style mutations of the dangerous corpus.

Every Bash bench case expected to be deny/ask is mutated
programmatically (quote fragments, backslash escapes, $IFS, tabs,
prefix segments, $(...) wrapping, subshell parens). A mutation is
"caught" when the mutated command is still denied or asked about.
The printed percentage is the GuardFall score — measured, never
targeted in advance. Mutations that soften a deny into an ask are
reported separately.

Usage: python3 bench/fuzz.py
"""

import importlib.util
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_bench import load_cases, load_hook  # noqa: E402


def _first_word(cmd):
    return cmd.split(None, 1)[0] if cmd.split() else ""


def mutations(cmd):
    out = []
    fw = _first_word(cmd)
    rest = cmd[len(fw):]
    if len(fw) >= 2 and fw[0].isalpha() and not re.search(r"['\"\\\\]", fw):
        # Well-formed quote fragmentation: the inserted quotes BALANCE
        # (r"m" -rf … / r'm' -rf …), which is how the evasion is
        # actually typed. An unbalanced quote is a syntax error in a
        # real shell, not an evasion. Fragment mutations only apply to
        # plain first words — fragmenting an already-quoted word
        # produces unbalanced quotes, i.e. the same non-evasion.
        out.append(("quote-fragment",
                    fw[0] + '"' + fw[1] + '"' + fw[2:] + rest))
        out.append(("quote-fragment-single",
                    fw[0] + "'" + fw[1] + "'" + fw[2:] + rest))
        out.append(("backslash-escape", "\\" + cmd))
    if rest.startswith(" "):
        out.append(("ifs", fw + "$IFS" + rest[1:]))
        out.append(("ifs-braced", fw + "${IFS}" + rest[1:]))
    out.append(("tabs", cmd.replace(" ", " \t ", 2)))
    out.append(("prefix-true", "true && " + cmd))
    out.append(("prefix-segment", "ls; " + cmd))
    out.append(("subst-wrap", "echo $(" + cmd + ")"))
    out.append(("subshell", "(" + cmd + ")"))
    out.append(("env-prefix", "env " + cmd))
    out.append(("command-prefix", "command " + cmd))
    if fw.isalpha() and fw.islower():
        out.append(("var-command", "X=%s; $X%s" % (fw, rest)))
    return out


def main():
    import tempfile
    from run_bench import _apply_fixture
    hook = load_hook()
    cases = [c for c in load_cases()
             if c["tool"] == "Bash" and c["expected"] in ("deny", "ask")]
    total = caught = softened = 0
    misses = []
    for case in cases:
        with tempfile.TemporaryDirectory() as td:
            if case.get("fixture"):
                _apply_fixture(td, case["fixture"])
            for kind, mutated in mutations(case["input"]["command"]):
                total += 1
                got = hook.evaluate_bash(mutated, cwd=td)["decision"]
                if got in ("deny", "ask"):
                    caught += 1
                    if case["expected"] == "deny" and got == "ask":
                        softened += 1
                else:
                    misses.append((case["name"], kind, mutated, got))
    score = 100.0 * caught / total if total else 0.0
    print("GuardFall score: %d/%d mutations caught = %.1f%%"
          % (caught, total, score))
    print("Softened (deny -> ask under mutation): %d" % softened)
    print("Mutations generated: %d (from %d dangerous cases)"
          % (total, len(cases)))
    if misses:
        print("Missed mutations (by name):")
        for name, kind, mutated, got in misses[:60]:
            print("  MISS %-40s %-18s got=%-5s %s"
                  % (name, kind, got, mutated[:90]))
        if len(misses) > 60:
            print("  ... and %d more" % (len(misses) - 60))
    return 0


if __name__ == "__main__":
    sys.exit(main())
