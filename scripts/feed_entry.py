#!/usr/bin/env python3
"""Scaffold a Disaster Feed entry (SHINE6 X3).

Project law (CONTRIBUTING.md): no detector ships without bench cases
(destructive AND benign near-miss) and a remediation string. This
tool enforces the bench half mechanically: it REFUSES to scaffold an
entry whose bench case ids are not already present in
bench/cases.jsonl. Write the bench cases first; then run this.

Usage:
  python3 scripts/feed_entry.py --id sl-2026-widget-meltdown \
      --incident "WidgetCo agent deleted the backups bucket" \
      --source-url "https://example.org/postmortem" \
      --rule-id seatbelt-locked-widget-delete \
      --bench-case destructive-widget-delete \
      --bench-case benign-widget-list
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", required=True)
    ap.add_argument("--incident", required=True)
    ap.add_argument("--source-url", required=True)
    ap.add_argument("--rule-id", action="append", required=True)
    ap.add_argument("--bench-case", action="append", default=[])
    ap.add_argument("--date", default="")
    args = ap.parse_args()

    cases_path = ROOT / "bench" / "cases.jsonl"
    known = set()
    for line in cases_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            known.add(json.loads(line)["name"])
    missing = [c for c in args.bench_case if c not in known]
    if not args.bench_case:
        print("REFUSED: no --bench-case given. Project law: no detector "
              "without bench cases (destructive AND benign near-miss). "
              "Add the cases to bench/cases.jsonl first.", file=sys.stderr)
        return 2
    if missing:
        print("REFUSED: bench case id(s) not found in bench/cases.jsonl: "
              + ", ".join(missing), file=sys.stderr)
        return 2

    index_path = ROOT / "feed" / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    if any(e["id"] == args.id for e in index["entries"]):
        print("REFUSED: feed entry %s already exists." % args.id,
              file=sys.stderr)
        return 2
    index["entries"].append({
        "id": args.id, "date": args.date or "TODO",
        "incident": args.incident, "source_url": args.source_url,
        "rule_ids": args.rule_id, "bench_case_ids": args.bench_case,
        "note": "TODO: one-line mapping note",
    })
    index_path.write_text(json.dumps(index, indent=1) + "\n", encoding="utf-8")

    stub = {
        "name": "feed-" + args.id,
        "description": "TODO: Disaster Feed entry %s — %s" % (args.id, args.incident),
        "deny_patterns": [],
        "ask_patterns": ["TODO-detector-pattern"],
    }
    rule_path = ROOT / "feed" / "rules" / (args.id + ".json")
    rule_path.write_text(json.dumps(stub, indent=1) + "\n", encoding="utf-8")

    changelog = ROOT / "CHANGELOG.md"
    line = ("- Feed: %s — %s (rules: %s; bench: %s)\n"
            % (args.id, args.incident, ", ".join(args.rule_id),
               ", ".join(args.bench_case)))
    text = changelog.read_text(encoding="utf-8") if changelog.exists() else ""
    if "## Unreleased" in text:
        text = text.replace("## Unreleased\n", "## Unreleased\n" + line, 1)
    else:
        text = "## Unreleased\n" + line + "\n" + text
    changelog.write_text(text, encoding="utf-8")

    print("Scaffolded feed entry %s:" % args.id)
    print("  feed/index.json        (entry appended)")
    print("  feed/rules/%s.json (stub — replace TODO patterns)" % args.id)
    print("  CHANGELOG.md           (Unreleased line added)")
    print("Next: implement the detector, fill the stub, run bench + tests.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
