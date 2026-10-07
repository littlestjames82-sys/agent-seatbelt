# Launch film — Agent Seatbelt (45–60s, vertical 1080×1920)

Per the studio's Build in Public rule: the film shows **built
artifacts and real numbers only**. Narration via Sopro V2 Turbo
(studio default voice). Lead with the explanation + real terminal
UI; mood second.

## Script

**0:00–0:06 — The hook.**
On screen: a terminal. An agent types `rm -rf ~/project`.
Narration: *"Your coding agent is one command away from deleting
your project. Mine was."*

**0:06–0:16 — The block.**
The command is stopped; the Seatbelt denial appears with rule id,
blast radius, and safer path.
Narration: *"Agent Seatbelt sits in front of every tool call. It
reads the command the way an attacker would write it —
deobfuscated — and stops the ones that end careers."*

**0:16–0:26 — The evasion.**
Type `r"m" -rf /` — normalized on screen to `rm -rf /` — denied.
Narration: *"Quote tricks, dollar-IFS, base64, aliases — the shell
games from this year's bypass research — normalized before they're
judged."*

**0:26–0:36 — The undo.**
An edit is snapshotted, deleted, then restored with
`/agent-seatbelt:restore`.
Narration: *"Before anything destructive runs, Seatbelt snapshots
what's about to be lost. Deleting the wrong file becomes an undo,
not a postmortem."*

**0:36–0:48 — The scoreboard.**
The bench table fills the screen: 206/206. The naive regex line:
42/206.
Narration: *"We publish the test. Two hundred and six cases —
Seatbelt scores two hundred and six. A single regex scores
forty-two."*

**0:48–0:58 — The close.**
Install commands type themselves: marketplace add, plugin install.
Bench score holds in the corner.
Narration: *"Agent Seatbelt. Free, open source, and already
watching. Two commands to install."*

End card: repo URL + "Bench v1: 206/206".
