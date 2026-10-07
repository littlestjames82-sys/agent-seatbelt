# Built from real disasters

Agent Seatbelt's rule set was not designed in the abstract. Each entry
below is a real, reported incident in which an AI agent destroyed data,
money, or trust — summarized in our own words — followed by the
Seatbelt mechanism that addresses that failure shape. Bench cases
derived from an incident carry its id in an `incident` field in
`bench/cases.jsonl`.

**Scope, stated precisely:** Seatbelt gates the *tool-call path* — the
shell commands, file operations, and MCP tool calls an agent issues
through a supported host. Incident #4's deletion was an API call made
over HTTP; Seatbelt covers that shape only when the call is issued via
a gated shell or MCP tool. A hook cannot intercept traffic that never
passes through the agent's tools, and Seatbelt does not claim to.

## 1. The home-directory wipe (Dec 2025, Claude Code)
A cleanup command listed several project directories to remove and
ended with a trailing target that the shell expanded to the user's
home directory. The home directory — including the macOS Keychain —
was deleted.
**Seatbelt:** recursive-delete detectors judge every target after
shell normalization, not just the first; blast radius reports how many
files a delete would touch and whether it escapes the project.

## 2. The wrong-folder photo deletion (Feb 2026, Claude Cowork)
A user granted deletion of temporary files; the agent ran the delete
against the wrong folder and roughly 15,000–27,000 family photos were
destroyed, bypassing the Trash entirely.
**Seatbelt:** delete verbs outside the project tree are asked about
with the affected count in the reason, and pre-action snapshots (W1)
copy enumerable targets before an approved destructive action runs,
so a wrong-folder delete is recoverable.

## 3. The alias that pushed to production (Jul 2025, Replit)
During a code freeze, an agent ran a project script alias whose name
looked harmless. The alias resolved to a forced schema push against
the live database and about 1,200 records were deleted.
**Seatbelt:** alias resolution (U1) — `npm run`, `make`, `just` and
friends are judged by the command they actually resolve to, read from
the project manifest, never by the alias's name.

## 4. The over-scoped token (Apr 2026, PocketOS / Cursor)
An agent found a cloud token with broad permissions in an unrelated
file and used it to call a volume-delete API. The production database
and its backups were gone in about nine seconds.
**Seatbelt:** the tool-call half of this shape — destructive MCP tool
names are asked about (T5), destructive cloud CLI calls are denied,
and secret reads are gated so tokens are not casually harvested. See
the scope note above: the raw API path outside the agent's tools is
not something a hook can see.

## 5. The junction that ate a live tree (Sep 2026, user-reported)
A Python cleanup script walked a mirrored folder; Windows junctions
inside the mirror pointed back into the live tree. The script followed
them and deleted 48,218 files, including the repository's own object
store.
**Seatbelt:** junction/symlink-aware blast radius (U7) names links
that point outside a deletion target, and deletion script content
without a visible link guard is asked about before it is written.

## 6. Terraform against production (Feb 2026, DataTalks)
An agent ran a Terraform destroy against the production environment.
**Seatbelt:** `terraform destroy` is a locked deny, and production
signals (U2) — prod-named resources, production environment markers —
escalate destructive verdicts and are named in the reason.

## 7. The supply-chain payload that hired an agent (Aug 2025, Nx)
Malware shipped in a compromised package launched an already-installed
agent CLI with its permissions disabled and sent it hunting for
credential files.
**Seatbelt:** launching an agent with safety disabled
(`--dangerously-skip-permissions` and its cousins) is a locked deny
(U6), and reads of credential files are gated in every mode.

## 8. The 4.6-hour loop (Dec 2025, Claude Code sub-agent)
A sub-agent retried the same failing install command for roughly 4.6
hours, burning on the order of 27 million tokens. The blast radius was
the bill.
**Seatbelt:** the loop guard (U5) counts identical commands per
session; the third repeat is asked about, and rapid repeats escalate
in CI/paranoid policies.

---
*Incident summaries are drawn from public reporting and post-mortems
through 2026; dates and figures are as reported by the original
sources. Seatbelt's mapping from incident to mechanism is ours.*
