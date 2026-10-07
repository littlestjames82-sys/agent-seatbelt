/*
 * Agent Seatbelt for OpenCode (EXPERIMENTAL, simulated-tested only).
 *
 * OpenCode's documented plugin API (opencode.ai/docs/plugins) is an
 * in-process JavaScript API, not a stdin/stdout hook: a plugin returns
 * hooks, and "tool.execute.before" can throw to block a tool call.
 * This shim maps the shared Seatbelt policy core (../mods/policy.js)
 * onto that contract:
 *
 *   deny  -> throw (blocks the call, reason shown to the agent)
 *   ask   -> throw (OpenCode's tool.execute.before has no ask of its
 *            own; blocking with the safer path named is the honest
 *            mapping — OpenCode's separate permission system is not
 *            driven from here)
 *   allow/defer -> return normally
 *
 * Not live-tested against a running OpenCode in this repo's build
 * environment; the mapping logic is unit-tested with simulated
 * (input, output) hook arguments (seatbelt-opencode.test.mjs).
 */
import policy from "../mods/policy.js";

export const SeatbeltOpenCodePlugin = async () => {
  return {
    "tool.execute.before": async (input, output) => {
      if (!input || input.tool !== "bash") return;
      const command = (output && output.args && output.args.command) || "";
      const verdict = policy.evaluateCommand(command);
      if (verdict.decision === "deny" || verdict.decision === "ask") {
        throw new Error(verdict.reason);
      }
    },
  };
};

export default SeatbeltOpenCodePlugin;
