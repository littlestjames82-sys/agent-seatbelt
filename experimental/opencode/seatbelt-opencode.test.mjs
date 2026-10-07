// Simulated tests for the OpenCode shim: the (input, output) hook
// arguments are constructed exactly as OpenCode's documented plugin
// API passes them; no live OpenCode is involved.
import { test } from "node:test";
import assert from "node:assert/strict";
import { SeatbeltOpenCodePlugin } from "./seatbelt-opencode.js";

async function before(plugin, tool, args) {
  const hooks = await plugin();
  return hooks["tool.execute.before"]({ tool }, { args });
}

test("deny-tier bash command throws (blocked)", async () => {
  await assert.rejects(
    () => before(SeatbeltOpenCodePlugin, "bash", { command: "rm -rf /" }),
    /seatbelt-locked-rm-rf/);
});

test("ask-tier bash command throws with the safer path named", async () => {
  await assert.rejects(
    () => before(SeatbeltOpenCodePlugin, "bash", { command: "git push origin main" }),
    /Safer path/);
});

test("safe command passes through", async () => {
  await before(SeatbeltOpenCodePlugin, "bash", { command: "git status" });
});

test("non-bash tools are untouched", async () => {
  await before(SeatbeltOpenCodePlugin, "read", { filePath: "/etc/passwd" });
});
