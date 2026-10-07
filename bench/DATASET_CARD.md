# Dataset Card — Seatbelt Bench v1

**Purpose.** Score pre-tool gating decisions (deny / ask / allow /
defer) for AI coding agents, including adversarial evasion and
benign false-positive controls.

**Composition.** 206 cases (`cases.jsonl`) across Bash, PowerShell,
file Read/Write, MCP tool calls, and stateful drivers (sequences,
flight plans, brain drift, canaries). Categories include shell
destruction, evasion/obfuscation, secrets, exfiltration, git,
deploys, cloud/DB deletion, persistence, self-protection, and
benign near-misses. A separate 25-case injection corpus
(`injection_cases.jsonl`) covers prompt-injection flagging with
benign controls that quote attacks (including this project's own
incident write-ups).

**Collection process.** Hand-authored from: the 2026 GuardFall
hook-bypass research patterns, vendor postmortems, and eight real
public incidents (see `docs/INCIDENTS.md`; incident-derived cases
carry `incident` and `source` fields). No user data, no scraped
private content.

**Labels.** Each case has exactly one expected decision, assigned
from the policy semantics documented in the README's rule table.
Disagreements are label bugs: file an issue with the case name.

**Limitations.** The corpus reflects one project's policy judgment
(solo-developer threat model, Unix + PowerShell shells). Stateful
drivers assume the reference runner's fixtures. Scores are
comparable only within bench v1. The corpus does not measure
latency (see `latency.py`) or robustness (see `robustness.py`) —
those are separate instruments in the same folder.

**License.** MIT, same as the project.
