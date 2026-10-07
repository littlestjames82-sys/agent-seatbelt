/*
 * Agent Seatbelt — experimental JS policy core (Claude Mods edition).
 *
 * EXPERIMENTAL. This is a JavaScript port of the CORE Bash rule pack
 * from hooks/seatbelt_hook.py — same rule ids, same tiers — for use
 * with Claude Code Mods and the docs/playground.html demo. The Python
 * hook remains the reference implementation and the full rule set;
 * this port covers the Bash deny/ask core plus blast-radius counting.
 *
 * Dual export: CommonJS (module.exports) for Node, and
 * globalThis.SeatbeltPolicy for a plain <script> tag (file:// safe).
 */
"use strict";

function normalizeCommand(command) {
  var s = String(command || "");
  // Collapse quote fragments: r"m -rf" -> rm -rf ; 'r'm -> rm
  s = s.replace(/(["'])([A-Za-z0-9_./-]*)\1/g, "$2");
  s = s.split("$IFS").join(" ").split("${IFS}").join(" ");
  s = s.replace(/\\(.)/g, "$1");
  s = s.replace(/[ \t]+/g, " ");
  return s;
}

function countRmTargets(normalized) {
  // Best-effort literal target count for blast radius in reasons.
  var m = normalized.match(/\brm\s+((?:-[a-zA-Z]+\s+)*)(.*)$/);
  if (!m) return 0;
  var rest = (m[2] || "").split(/[;|&]/)[0].trim();
  if (!rest) return 0;
  return rest.split(/\s+/).filter(function (t) {
    return t && t[0] !== "-";
  }).length;
}

var DENY = [
  ["seatbelt-locked-rm-rf", /\brm\s+(?:[^;&|]*\s)?-[a-z]*r[a-z]*f\b|\brm\s+(?:[^;&|]*\s)?-[a-z]*f[a-z]*r\b/i,
    "recursive forced delete (rm -rf) can wipe a machine in one call"],
  ["seatbelt-locked-disk-destroy", /\bmkfs(\.[a-z0-9]+)?\b|\bdd\b[^;&|]*\bof=\/dev\//i,
    "formatting or raw-writing a device destroys everything on it"],
  ["seatbelt-locked-fork-bomb", /:\(\)\s*\{\s*:\|:&\s*\}\s*;?\s*:/,
    "this is a fork bomb"],
  ["seatbelt-locked-pipe-to-shell", /\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da|a)?sh\b/i,
    "piping a remote download straight into a shell runs unreviewed code"],
  ["seatbelt-locked-base64-hidden", /\bbase64\b[^|]*(--decode|-d)\b[^|]*\|\s*(ba|z)?sh\b/i,
    "a base64 blob decoded straight into a shell hides its payload"],
  ["seatbelt-locked-git-destroy", /\bgit\s+push\b[^;&|]*(--force|-f)\b[^;&|]*\b(main|master)\b|\bgit\s+push\b[^;&|]*\b(main|master)\b[^;&|]*(--force|-f)\b/i,
    "force-pushing over main/master rewrites shared history"],
  ["seatbelt-locked-cloud-delete", /\baws\s+[\w-]+\s+(delete-[\w-]+|terminate-instances)\b|\bgcloud\b[^;&|]*\bdelete\b|\bterraform\s+destroy\b/i,
    "cloud deletion is usually irreversible"],
  ["seatbelt-locked-database-drop", /\b(drop\s+(database|table)|truncate\s+table)\b/i,
    "dropping or truncating destroys data outright"],
  ["seatbelt-locked-agent-bypass", /--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--permission-mode\s+bypassPermissions/i,
    "launching an agent with permission checks disabled removes every other protection"],
];

var ASK = [
  ["seatbelt-locked-deploy-publish", /\b(npm|pnpm|yarn)\s+publish\b|\bdocker\s+push\b|\bgh\s+release\s+create\b|\bgit\s+push\b|\bvercel\b[^;&|]*(deploy|--prod)|\bfirebase\s+deploy\b|\bterraform\s+apply\b/i,
    "deploys and publishes affect people beyond this machine"],
  ["seatbelt-locked-git-discard", /\bgit\s+(reset\s+--hard|clean\s+-[a-z]*f|checkout\s+--\s|restore\s+\.)\b/i,
    "this discards uncommitted work"],
  ["seatbelt-locked-rm", /\brm\b/i, "file deletion is not undoable from here"],
  ["seatbelt-locked-sudo", /\bsudo\b/i, "elevated privileges deserve a human look"],
  ["seatbelt-locked-global-install", /\bnpm\s+(install|i)\s+[^;&|]*\s-g\b|\bpip\s+install\s+--user\b/i,
    "global installs change the machine, not the project"],
  ["seatbelt-locked-secret-read", /\b(cat|head|tail|less|more|cp|mv|base64|xxd|od)\b[^;&|]*(\.env\b|\.aws\/|id_rsa|credentials\b)/i,
    "this touches credential material"],
  ["seatbelt-locked-permissions", /\bchmod\b[^;&|]*(\b777\b|-R\b)|\bchown\s+-R\b/i,
    "recursive or world-writable permission changes are hard to undo"],
  ["seatbelt-locked-system-control", /\bkill\s+-9\b|\bkillall\b|\bsystemctl\s+(stop|restart|disable|mask)\b/i,
    "this stops processes or services"],
];

var REMEDIATIONS = {
  "seatbelt-locked-rm-rf": "List the exact paths (ls) and delete them one at a time, or move them to a trash folder first.",
  "seatbelt-locked-pipe-to-shell": "Download the script to a file, read it, then run it.",
  "seatbelt-locked-git-destroy": "Push to a branch and open a PR instead of force-pushing main.",
  "seatbelt-locked-deploy-publish": "Deploy a preview/staging build first and confirm the target.",
  "seatbelt-locked-git-discard": "Run git stash or git diff first so the work is recoverable.",
  "seatbelt-locked-rm": "Move the file to a trash folder, or list it first with ls.",
  "seatbelt-locked-sudo": "Run without sudo if possible; if root is truly required, a human should run it.",
  "seatbelt-locked-secret-read": "Reference the variable name, not the value; never print credential contents.",
};

var SAFE = [
  /^\s*(ls|pwd|echo|cat\s+[^;&|]*\.(md|txt|json)\b|git\s+(status|log|diff|branch)\b|npm\s+(test|run\s+test)\b|node\s+--version|python3?\s+--version)/i,
];

function hasSecretRef(s) {
  return /(\.env\b|\.aws\/credentials|id_rsa|api[_-]?key|secret|token)/i.test(s);
}
function hasNetwork(s) {
  return /\b(curl|wget|nc|ncat|scp|sftp|rsync)\b|https?:\/\//i.test(s);
}

function evaluateCommand(command) {
  var normalized = normalizeCommand(command);
  var i, rule;
  // Secret exfiltration: secret material + a network tool in one command.
  if (hasSecretRef(normalized) && hasNetwork(normalized) &&
      /\b(curl|wget|nc|ncat|scp|sftp)\b/i.test(normalized)) {
    return verdict("deny", "seatbelt-locked-secret-exfil",
      "this command reads secret material and sends data over the network",
      normalized);
  }
  for (i = 0; i < DENY.length; i++) {
    rule = DENY[i];
    if (rule[1].test(normalized)) return verdict("deny", rule[0], rule[2], normalized);
  }
  for (i = 0; i < ASK.length; i++) {
    rule = ASK[i];
    if (rule[1].test(normalized)) return verdict("ask", rule[0], rule[2], normalized);
  }
  for (i = 0; i < SAFE.length; i++) {
    if (SAFE[i].test(normalized)) return verdict("allow", "seatbelt-safe", "known-safe read-only command", normalized);
  }
  return verdict("defer", "none", "no rule matched; deferring to the host's own approval flow", normalized);
}

function verdict(decision, ruleId, why, normalized) {
  var out = {
    decision: decision,
    ruleId: ruleId,
    reason: "",
    remediation: REMEDIATIONS[ruleId] || "",
    normalized: normalized,
  };
  if (decision === "deny" || decision === "ask") {
    var targets = countRmTargets(normalized);
    var blast = targets > 0 ? " Blast radius: " + targets + " literal target(s)." : "";
    out.reason = "Seatbelt " + decision.toUpperCase() + " [" + ruleId + "]: " + why + "." + blast +
      (out.remediation ? " Safer path: " + out.remediation : "");
  }
  return out;
}

var api = {
  evaluateCommand: evaluateCommand,
  normalizeCommand: normalizeCommand,
  version: "0.2.0",
};

if (typeof module !== "undefined" && module.exports) {
  module.exports = api;
}
if (typeof globalThis !== "undefined") {
  globalThis.SeatbeltPolicy = api;
}
