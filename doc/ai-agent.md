# AI agent

The agent is any command that reads the prompt on stdin. Set it with `GHAV_AI`.

| Value | Notes |
| --- | --- |
| `claude -p` | default |
| `codex exec -` | |
| `pmai "$(cat)"` | reads the prompt from the argument instead of stdin |

In the TUI, `A` cycles between these three presets.

## What the agent sees

The agent runs in the current directory, so it can inspect the checkout, `git log`, tags and
`gh`, and build and run reproducers against vulnerable and patched revisions.

The prompt asks for brief notes first (verdict, confidence, doubts), then the advisory as the
last block of the reply, in the format from [advisory-format.md](advisory-format.md), without
code fences.

## What it is told to care about

- whether the patch is actually a security fix
- root cause, attack surface, CWE and CVSS
- first affected and first fixed release — never assume every release before the fix is
  vulnerable; check tags and backports
- duplicates; one commit may fix several bugs, several commits may share one root cause
