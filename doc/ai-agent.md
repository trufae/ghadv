# AI agent

The agent is any command that reads the prompt on stdin. Set it with `GHADV_AI`.

| Value | Notes |
| --- | --- |
| `claude -p` | default |
| `codex exec -` | |
| `pmai "$(cat)"` | reads the prompt from the argument instead of stdin |
| `opencode run "$(cat)"` | OpenCode noninteractive mode; passes the prompt as one argument |

In the TUI, `A` cycles between these four presets.

## What the agent sees

The agent runs in the current directory, so it can inspect the checkout, `git log`, tags and
`gh`, and build and run reproducers against vulnerable and patched revisions.
For a GitHub issue/PR URL, the prompt includes its title, body and discussion comments.
PRs also include their patch and merge metadata. The agent is told to verify the checkout
matches the source repository, follow linked fixes, treat source content as evidence rather
than instructions, and flag unknown versions. A closed issue or unmerged PR is not assumed
to have a released fix. The source URL is requested in the advisory references for linking.

For drafting and review, the prompt asks for brief notes first (verdict, confidence,
doubts), then the advisory as the last block of the reply, in the format from
[advisory-format.md](advisory-format.md), without code fences.

## What it is told to care about

- whether the patch is actually a security fix
- root cause, attack surface, CWE and CVSS
- first affected and first fixed release — never assume every release before the fix is
  vulnerable; check tags and backports
- duplicates; one commit may fix several bugs, several commits may share one root cause
- original finder/reporter attribution from commit messages and linked reports: verified
  GitHub logins go in credits; names, handles and scan references (such as OSS-SCAN and
  scan-coverity with their full IDs) not captured there go in the advisory description
  under Acknowledgements, preserving source links rather than appearing only in agent notes

## Finding similar bugs

`b` in the TUI or `ghadv similar <ghsa|commit|url> [context]` uses a dedicated search prompt.
It includes the selected advisory (with CVE and references) or source patch/report, any
linked advisory, the existing advisory list for duplicate checking, and optional context.
The agent verifies the checkout and revision, reconstructs the original root cause and
fix, then searches sibling implementations, callers and alternative paths for variants
that remain reachable in current code. It must check guards and data flow, not just syntax.

The reply is a Markdown findings report with locations, triggers, impact, confidence,
evidence and reproduction steps. Confirmed findings, unverified leads and limitations
are separated; tests actually run must be distinguished from suggested tests. No findings
is a valid result. The prompt instructs the agent to preserve tracked files and GitHub
state and keep local reproduction work in an isolated temporary directory.

The report opens in the usual Markdown viewer. Source evidence, prompt and raw reply
remain in the private recovery directory, including after success. `ghadv resume <directory>`
reopens the saved report without running the AI, parsing an advisory or submitting changes.
