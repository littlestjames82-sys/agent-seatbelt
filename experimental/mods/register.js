/*
 * Agent Seatbelt — Claude Mods registration shim (EXPERIMENTAL).
 *
 * Claude Code Mods (2.1.287+, Oct 2026) run JavaScript IN-PROCESS in
 * Claude Code, unsandboxed, with the user's permissions. Anthropic's
 * docs note that a mod which approves tool calls can approve one a
 * PreToolUse hook blocked, and that mods should be treated as trusted
 * code. This shim therefore does the minimum: it registers the shared
 * policy core (./policy.js) as a pre-tool check that can only ever
 * BLOCK or flag — it never approves on the hook's behalf, and the
 * Python hook remains the enforcement floor.
 *
 * NOT live-tested against a real Mods runtime in this repo's build
 * environment; the decision logic is unit-tested (policy.test.mjs),
 * the registration surface follows Anthropic's published Mods shape
 * as of Oct 2026 and may drift. See experimental/README.md.
 */
"use strict";

let policy = null;
if (typeof require !== "undefined") {
  try {
    policy = require("./policy.js");
  } catch (e) {
    policy = null;
  }
}
if (!policy && typeof globalThis !== "undefined") {
  policy = globalThis.SeatbeltPolicy || null;
}

/**
 * Evaluate a tool call the way a Mods pre-tool hook would receive it.
 * Returns {block: boolean, reason?: string} — block-only semantics.
 */
function seatbeltModCheck(toolName, toolInput) {
  if (!policy) return { block: false, reason: "policy core not loaded" };
  if (toolName !== "Bash") return { block: false };
  const command = (toolInput && toolInput.command) || "";
  const verdict = policy.evaluateCommand(command);
  if (verdict.decision === "deny") {
    return { block: true, reason: verdict.reason };
  }
  if (verdict.decision === "ask") {
    // A mod cannot raise a native ask the way a hook can; surface the
    // concern as a block with the safer path named, so a human decides
    // out of band. This is stricter than the hook on purpose.
    return { block: true, reason: verdict.reason };
  }
  return { block: false };
}

// Registration entry point used by Mods loaders that scan for a
// default export / named hook functions. Kept deliberately small.
const SeatbeltMod = {
  name: "agent-seatbelt",
  version: "0.2.0",
  experimental: true,
  checkToolCall: seatbeltModCheck,
};

if (typeof module !== "undefined" && module.exports) {
  module.exports = SeatbeltMod;
}
if (typeof globalThis !== "undefined") {
  globalThis.SeatbeltMod = SeatbeltMod;
}
