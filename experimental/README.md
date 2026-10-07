# Experimental editions

Everything in this folder is **experimental**: promising surfaces where
Seatbelt's policy core runs somewhere other than the Python hook, kept
honest about what is and isn't proven.

## mods/ — Claude Code Mods edition + shared JS policy core

`mods/policy.js` is a JavaScript port of the hook's **core Bash rule
pack** — same rule ids, same deny/ask tiers, shell normalization
(quote fragments, `$IFS`), blast-radius counts, and remediations. The
Python hook remains the reference implementation with the full rule
set (file gating, MCP, snapshots, injection, flight plans, brain
watch — none of that is in the JS port).

`mods/register.js` adapts the policy to Claude Code's Mods surface
with block-only semantics.

**The honesty note that matters:** Claude Mods run unsandboxed,
in-process, with your permissions, and per Anthropic's documentation
a mod that approves tool calls *can approve one that a PreToolUse hook
blocked*. Treat any mod — including this one — as trusted code you
have read. The hook is the deterministic floor; mods are not a
replacement for it. The built-in `sec-default` mod loads first on
Team/Enterprise/managed setups.

Status: decision logic unit-tested (`node --test
experimental/mods/policy.test.mjs`, including a parity spot-check
against Seatbelt Bench verdicts). **Not live-tested** against a real
Mods runtime from this repo's build environment.

## opencode/ — OpenCode plugin shim

OpenCode's plugin API is documented and in-process: a plugin's
`tool.execute.before` hook receives `(input, output)` and blocks by
throwing. `opencode/seatbelt-opencode.js` maps the shared policy core
onto that contract (deny → throw; ask → throw with the safer path
named, since the hook has no ask of its own). Simulated tests:
`node --test experimental/opencode/seatbelt-opencode.test.mjs`.
**Simulated-tested, not live-tested.**

## The playground

`docs/playground.html` loads `mods/policy.js` directly and evaluates
commands in the browser — open it from disk, no server, no network.
