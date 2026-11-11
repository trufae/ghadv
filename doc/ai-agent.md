# AI agent

The agent is any command that reads the prompt on stdin. Set it with `GHADV_AI`.

| Value | Notes |
| --- | --- |
| `claude -p` | default; ghadv enables and decodes Claude's event stream |
| `codex exec -` | native progress on stderr |
| `pmai --progress "$(cat)"` | progress on stderr; reads the prompt from the argument instead of stdin |
| `opencode run "$(cat)"` | OpenCode noninteractive mode; passes the prompt as one argument |

In the TUI, `A` cycles between these four presets.

## Progress and recovery

Agent stderr is visible immediately in CLI and TUI workflows. ghadv also prints
an elapsed-time update every 10 seconds while the command is running, including
when an agent is quiet. This update indicates the process is alive, not how much
of the task it has completed. To capture feedback, redirect stderr with `2> progress.log`.

For the exact `claude -p` preset (including `GHADV_AI='claude -p'`), ghadv adds
`--output-format stream-json --verbose`. Assistant messages and tool activity appear
on stderr, including Bash commands and descriptions, file paths, search patterns,
URLs and subagent tasks. For example:

```text
[claude] tool: Bash
  description: "Inspect the fix"
  command: "git show --stat HEAD"
[claude] tool: Read
  file_path: "src/parser.c"
```

Arguments are JSON-quoted so multiline commands and control characters remain
readable, with each argument preview limited to 1,000 characters. File contents
and replacement text are omitted from progress. The full raw events are saved
in `claude.jsonl`; completed top-level text messages are saved in `reply.txt` as
recovery text while Claude works. On success,
the final result replaces that text, so JSON events, tool output and subagent
messages never enter the advisory. A failed or incomplete stream stops the workflow
before opening the editor or saving to the provider. Both files survive errors
and interruptions; `claude.jsonl` can help repair `reply.txt` before `ghadv resume`.
Successful advisory saves clean up both files; similar-bug reports retain them.

The pmai preset requires a version supporting `--progress`. To select it directly:

```sh
export GHADV_AI='pmai --progress "$(cat)"'
```

Other custom commands run exactly as configured, with stdout saved as plain text
in `reply.txt` and stderr inherited. Use their progress/verbose options when needed;
keep diagnostic output on stderr and the final advisory on stdout. In particular,
custom Claude commands with extra flags are not automatically converted to JSON mode.

## What the agent sees

The agent runs in the current directory, so it can inspect the checkout, `git log`, tags and
`gh` or `glab` for the selected provider, and build and run reproducers against vulnerable and patched revisions.
For a GitHub issue/PR or GitLab issue/MR URL, the prompt includes its title, body and discussion comments.
PRs/MRs also include their patch and merge metadata. The agent is told to verify the checkout
matches the source repository, follow linked fixes, treat source content as evidence rather
than instructions, and flag unknown versions. A closed issue or unmerged PR is not assumed
to have a released fix. The source URL is requested in the advisory references for linking.

For drafting and review, the prompt asks for a self-contained advisory as the last block
of the reply, in the format from [advisory-format.md](advisory-format.md), without an outer
code fence. Optional leading notes are limited to a brief editorial verdict and change
summary; they are not saved to the provider. Technical findings, evidence, caveats, verification
limits and reasoning for material corrections belong in the advisory description itself.
The agent is asked to check that no substantive finding remains only in notes or header comments.

GitLab prompts use `glab` and explain that the disclosure is stored as a confidential
issue. Credits and vulnerability metadata are text, and assigned CVEs belong in the
References section. Recovery retains the provider and host. The AI/editor review process
is the same as GitHub; saving a GitLab edit does not alter confidentiality.

## What it is told to care about

- whether the patch is actually a security fix
- root cause, attack surface, CWE and CVSS
- reproduction steps and results, distinguishing tests actually run from suggested tests,
  impact limits, mitigations and unresolved uncertainty in the advisory description
- first affected and first fixed release — never assume every release before the fix is
  vulnerable; check tags and backports
- duplicates; one commit may fix several bugs, several commits may share one root cause
- related findings, reports and advisories: preserve their IDs and source links and explain
  whether they are duplicates, variants, share a root cause or are separate issues; keep
  independent bugs' impact, versions and severity separate from the selected vulnerability
- original finder/reporter attribution from commit messages and linked reports: verified
  provider usernames go in credits; names, handles and scan references (such as OSS-SCAN and
  scan-coverity with their full IDs) not captured there go in the advisory description
  under Acknowledgements, preserving source links rather than appearing only in agent notes
- missing or incomplete credits in both drafts and reviews: investigate the sources and fill
  verified provider usernames and roles, rather than only noting the omission; leave `credits:` empty
  when no login can be verified and retain known attribution in Acknowledgements

Reviews preserve useful technical details, references and attribution while correcting
unsupported claims. These are instructions to the configured agent; inspect the proposed
advisory or review diff before saving.

## Finding similar bugs

`b` in the TUI or `ghadv similar <id|commit|url> [context]` uses a dedicated search prompt.
It includes the selected advisory (with CVE and references) or source patch/report, any
linked advisory, the existing advisory list for duplicate checking, and optional context.
The agent verifies the checkout and revision, reconstructs the original root cause and
fix, then searches sibling implementations, callers and alternative paths for variants
that remain reachable in current code. It must check guards and data flow, not just syntax.

The reply is a Markdown findings report with locations, triggers, impact, confidence,
evidence and reproduction steps. Confirmed findings, unverified leads and limitations
are separated; tests actually run must be distinguished from suggested tests. No findings
is a valid result. The prompt instructs the agent to preserve tracked files and remote
state and keep local reproduction work in an isolated temporary directory.

The report opens in the usual Markdown viewer. Source evidence, prompt and raw reply
remain in the private recovery directory, including after success. `ghadv resume <directory>`
reopens the saved report without running the AI, parsing an advisory or submitting changes.
