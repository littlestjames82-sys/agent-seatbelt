# Agent Seatbelt — Release Security Audit (0.3.2 audit cycle)

Status: Complete. Audit executed October 14, 2026 against the
0.3.1 release tree; remediation verified the same day (results in
the verification section below).

## Scope

- Audited tree: repository main at commit 1eea6605 (the 0.3.1 release
  tree plus the Phase 1 documentation reconciliation and the CI
  executable-mode fix), file-for-file verified against the remote
  (109 of 109 tracked source files matched by blob hash).
- Component audited: hooks/seatbelt_hook.py (the single-file,
  stdlib-only PreToolUse hook), its policy loading, audit log,
  snapshot/restore path, and the packaging path (sdist/wheel build).
- Method: adversarial bypass probing with freshly generated payloads
  disjoint from the bench corpus, a robustness battery, an audit-log
  integrity exercise, and a supply-chain build check. Every probed
  finding was re-verified by hand against the live hook process
  before a fix was written.

## Robustness battery

Run against the audited tree (the release code as shipped):
10,000 of 10,000 in-process payloads processed with zero failures
(no crashes, hangs, or malformed outputs), and 300 of 300
subprocess envelopes (the hook driven exactly as a host drives it)
with zero failures. Verdict: PASS. The battery measures the shipped
code; the remediated tree's verification is the section below.

## Adversarial probing (before remediation)

232 fresh payloads across new mutation families (encoding, config
plane, envelope shapes, interpreter coverage, two-step chains,
container/cloud tiers). Classification of outcomes:

- 42 payloads were real bypasses (verdict defer/allow where the
  payload was destructive), 36 classified findings.
- 11 softening findings, 14 known/documented limits, 165 correct.
- No crashes, no hangs; worst observed latency 928 ms on a 100 KB
  payload.

After remediation, the same 232 payloads were replayed against the
fixed hook. Of the 36 classified bypass findings, 35 are replayable
envelopes (the 36th, the fail-open envelope shape, is covered by
the new pytest file instead): 27 now deny and 8 now ask; none still
passes. All 11 softening findings hardened (4 deny, 7 ask). No
previously-correct verdict on a destructive payload weakened, and
no benign payload newly denies.

## Findings and remediation

### 1. Project policy could loosen the mode (critical, config plane)
A project-level .seatbelt/policy.json carrying
{"seatbelt_mode": "audit"} downgraded every locked deny to log-only.
The agent cannot plant that file (writes under .seatbelt are themselves
blocked), but an untrusted checkout ships it. Fix: a project overlay
may only tighten (strict); loosening requests are recorded and
ignored. SEATBELT_MODE in the host environment remains the human's
own switch and outranks any overlay.

### 2. Malformed envelopes failed open
Valid JSON with wrong shapes (tool_input as a bare string, a
non-string or null command, a missing tool_name, differently-cased or
unknown tool names carrying a command) deferred instead of failing
closed. Fix: a shape gate ahead of classification returns an
audit-logged deny for gated tool shapes; tool names are
canonicalized case-insensitively; an unknown tool carrying a string
command is classified as Bash.

### 3. Destructive peers with no rules
wipefs, blkdiscard, nvme format, sgdisk, hdparm erase, writes to
/proc/sysrq-trigger, broad or unfiltered find -delete, setuid chmod,
userdel/groupdel, journalctl vacuum, git checkout . (discard tree),
and writes to cron spool / systemd unit / LaunchAgents paths had no
deny or ask coverage. All are covered now, at the tiers in the bench.

Calibration note: a filtered find -delete inside a subdirectory of
the home tree stays ask, not deny. That tier is set by a shipped
incident-derived bench case; the deny tier is reserved for find
-delete from a broad root or with no narrowing filter at all.

### 4. Decoder pipelines reconstructed commands unseen
printf octal escapes, ANSI-C $'...' quoting, rev, xxd -r and ROT13
tr pipelines could rebuild a destructive command that the classifier
never saw. Fix: a decoded-forms verdict decodes those literals and
classifies the result. Plain unescaped printf data is deliberately
not judged, so writing a command string to a file stays allowed;
parity with the existing base64 treatment applies to encoded forms.

### 5. Interpreter coverage gaps
Python heredoc bodies (shell heredocs were already scanned),
subprocess list-form with concatenated literals, perl list-form
system and remove_tree, ruby FileUtils.rm_rf and File.delete on
system paths, node fs rmSync on a root path, shutil.rmtree over
expanduser('~'), and Rscript unlink recursive on a root path slipped
past the code rules. All covered now.

### 6. Two-step and sourced execution
source/. on a script file deferred (the bash form was already
content-scanned), and download-then-execute in a single command
(curl -o file followed by running that file) deferred. Both are
classified now; the normalized-text pass also catches the mutated
forms (variable command names, $IFS insertion, quote fragmentation,
subshell wrapping), which the GuardFall fuzz verifies.

### 7. Container, cloud and exfiltration tiers
kubectl delete --all / --all-namespaces, docker prune with volumes,
rsync/rclone copies whose source is a secret file to a remote
destination, secret files sent over /dev/tcp, and the PowerShell
Clear-Disk / Format-Volume cmdlets are now denied or asked at the
tiers the bench records. Scoped operations (a named kubectl delete,
a plain docker prune, a local rsync) still defer or ask as before.

### 8. Residual findings closed in a fifth batch
Replaying the probing corpus against the remediated hook surfaced
six residual items in the same families, all closed: a ROT13 tr
pipeline using the alternate set spelling (a-zA-Z to n-za-mN-ZA-M),
now handled by translating literals through any equal-length tr
set pair rather than matching one spelling; DNS lookups whose query
is built by command substitution (deny when the substitution reads
a secret, ask otherwise), with a plain lookup and a local key
fingerprint check as passing near-misses; PowerShell Start-Process
with a hidden window (ask); Disable-ScheduledTask on a
security-named task (deny; generic task ask); and docker compose
down with volumes (ask).

### 9. Judgment call kept, not forced
A newline-split rm (rm\n-rf\n/) remains ask rather than deny: as
written it is not executable as one destructive command in bash, so
ask is the proportionate tier. Recorded here rather than silently
tightened.

## Audit-log integrity exercise

- A clean log verifies OK (hash chain intact).
- Flipping a recorded verdict in the middle of the log is detected:
  verification fails at the altered line, exit 1.
- A snapshot is taken before an ask-tier destructive command and
  restore returns the file byte-identical; restore is additive-only.
- Confirmed limit: silently truncating the TAIL of the log is not
  detectable by the hash chain alone. The log is tamper-evident, not
  tamper-proof, and the documentation should keep saying exactly that.

## Supply chain

Building an sdist from a tree where the hook has run used to ship
.seatbelt/audit.jsonl (live command history) inside the archive,
because .seatbelt/ was neither git-ignored nor excluded from the
build. The published 0.3.1 sdist was clean only because release
builds happen from a fresh checkout. Fix: .seatbelt/ added to
.gitignore and an explicit hatch build exclusion. Verified: a
deliberately dirtied tree now builds an sdist with zero state files.
The wheel declares zero runtime dependencies; twine check passes
for both artifacts.

## Verification of the remediated tree

- Bench corpus: 272 cases (221 shipped + 51 added for this audit,
  every fix with a benign near-miss): 272/272, 0 false positives.
- GuardFall fuzz over the enlarged corpus: 1,853/1,853 mutations
  caught, 0 misses, 4 deny-to-ask softenings (same count as the
  0.3.1 baseline).
- Injection bench: PASS. Selftest: 68/68.
- Full pytest suite: 379 passed, 0 failed (363 shipped tests plus
  the 16 new Phase 2 tests). An earlier run passed 378 of 379; the
  single failure was a missing remediation text for the new
  docker-prune rule, fixed before this run.

## Limitations

- This is a pattern classifier in front of a shell, not a sandbox.
  It raises the cost of destructive accidents and naive evasion; a
  determined adversary with arbitrary code execution should be
  assumed able to route around any string classifier eventually.
  OS-level isolation is a separate, later phase and is not claimed
  here.
- Coverage claims are exactly as wide as the corpora named above:
  the 272-case bench, the GuardFall mutation space, the injection
  bench, and this audit's 232 probing payloads. Nothing here is a
  held-out or third-party evaluation; that is Phase 5 of the work
  plan.
- Audit mode and shadow mode remain available as the human's own
  setting via the host environment. Project files cannot select
  them (finding 1).
