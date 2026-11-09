# ghav

**GitHub security advisories from the command line, written in [V](https://vlang.io).**

Turn a fix commit, issue or pull request into a published security advisory — with your AI agent doing the
reconstruction and you keeping the last word.

```
$ cd ~/radare2
$ ghav new 8f3a2c1 found by fuzzing the PDB parser

  [claude] reading the patch, checking tags and history...
  severity: high  cwe: CWE-787  affected: >= 4.5.1, < 6.2.2  patched: 6.2.2
  → opening $EDITOR... saved as draft GHSA-xxxx-yyyy-zzzz
```

## What it does

- **Lists** your repo's advisories, local fix commits (`##crash`, `##security`), and labeled issues/PRs.
- **Drafts** an advisory from a commit or GitHub issue/PR URL: the agent reads the report, discussion, patch when available, history and
  tags, and writes root cause, CWE, CVSS and the affected/patched versions.
- **Reviews** existing advisories with the agent as a diff you accept or reject line by line.
- **Finds similar bugs** using an advisory, its CVE or a fix commit as a template for an AI search.
- **Manages credits** in a dedicated TUI screen for finders, reporters, fix authors and
  other contributors, with a picker explaining every supported role.
- **Requests CVEs**, including for published advisories, accepts private reports as drafts,
  publishes and closes. TUI actions ask for confirmation.
- **Stays out of the way**: advisories are plain text in `$EDITOR`, no JSON, no web forms.

The API is easy; reconstructing the vulnerability is hard. `ghav` puts the hard part in front
of an agent that can actually run `git`, read the code and build reproducers — then hands you
the patch for approval.

## Install

Requires [V](https://vlang.io), `git` and an authenticated `gh` with
**Repository security advisories: write** permission.

```sh
git clone <this repo> && cd ghav
make BIN=ghav install # builds and installs ghav into ~/.local/bin
```

Or build only: `make` (defaults to `ghadv`), or `v -o ghav .` for the name used here.
`BIN`, `PREFIX` and `BINDIR` are overridable; `make uninstall` and `make clean` exist too.
Use the same `BIN` value when installing, uninstalling or cleaning. Compile the directory
so V includes every source file.

Run the focused source, advisory-link and review-diff tests with
`v test ghadv_test.v workflow_test.v credits_test.v`. After building, run
`python3 test/workflow.py /path/to/ghav` for recovery checks,
`python3 test/credits.py /path/to/ghav` for the credits TUI and API checks,
`python3 test/similar.py /path/to/ghav` for similar-bug searches, and
`python3 test/filters.py /path/to/ghav` for state/text filters and filtered navigation,
and `python3 test/cve.py /path/to/ghav` for CVE request persistence and status.
These use stub commands and do not access GitHub or run an AI agent.

The source files share one V module:

| File | Responsibility |
| --- | --- |
| `ghadv.v` | argument parsing, help and command dispatch |
| `github.v` | repository-scoped `GitHub` API, `gh` requests, endpoints and JSON serialization |
| `tui.v` | terminal views, row formatting, navigation and action prompts |
| `workflow.v` | draft creation, AI review and bug searches, editor handling and review diffs |
| `advisory.v` | advisory types, editable format parsing and source linking |
| `sources.v` | commit/issue/PR URL parsing and local fix-commit discovery |

The CLI and workflows call methods such as `api.advisories(state)`,
`api.create_advisory(advisory)` and `api.request_cve(id)`; GitHub endpoint paths and
payload handling stay in `github.v`.

## Usage

```
ghav [-r owner/repo] [command] [args]

  tui [label]             advisory, commit and labeled issues/PRs tabs (default)
  ls [state]              list all/triage/draft/published/closed advisories
  log                     list fix commits and their advisories
  issues [label]          list labeled issues/PRs (default: GHAV_LABEL or cve)
  new <commit|url> [context] analyze a commit, issue or PR with AI and create a draft
  show <ghsa>             print an advisory
  status <ghsa>           show lifecycle, CVE and private report details
  credits <ghsa>          manage credited people and roles in the TUI
  edit <ghsa>             edit an advisory in $EDITOR
  review <ghsa> [context] AI-review and rewrite it, then edit
  similar <ghsa|commit|url> [context] find similar bugs using the selection as a template
  resume <directory>     continue saved work without running the AI again
  cve <ghsa>              request a CVE id (asynchronous)
  approve <ghsa>          alias for cve
  draft <ghsa>            accept a report or reopen as a draft
  publish <ghsa>          publish
  close <ghsa>            close (reject)
```

Run `ghav` with no arguments for the TUI: advisory, fix-commit and labeled issues/PRs views, `tab` to
switch, `m` for the selected advisory's actions, `c` to request a CVE, `s` for status,
and `f`/`F` to cycle the state filter forward/backward. Two rows of colored shortcuts show
navigation and the actions available for the selection; `?` shows all keys. Use `j`/`k`
or the mouse wheel to move down/up one row in the active list.

Advisory and commit lists (also `ls` and `log`) show severity circles:
🔴 critical, 🟠 high, 🟡 medium, 🟢 low, and ⚪ unknown. Commits use a linked advisory's
severity when available; otherwise, a case-insensitive keyword estimate from the subject.
The hardcoded keywords come from radare2 `##crash` commits: command/shell injection and
sandbox escapes rank critical; UAF, double free, type confusion and buffer overflows rank
high; over-reads, integer overflow and resource exhaustion rank medium; null dereferences,
segfaults and leaks rank low. The strongest matching category wins. Tags alone do not set
severity, and unmatched subjects stay unknown. These estimates only affect display;
they do not set advisory severity or CVSS scores.

Press `/` to filter the current list by text, ignoring case. Enter applies the query;
an empty query clears it, and Escape or Ctrl+C cancels. Each tab keeps its own text filter,
which matches row data such as titles, IDs and linked advisories. Advisory text and state
filters combine. The active query appears above the shortcuts.

Press `r` to review the selected advisory. The optional extra-context prompt includes an
example, such as "Check the affected versions and whether the fix addresses the root
cause." Enter starts the review; Ctrl+C or Escape cancels and returns to the list.
The proposed patch opens in `$EDITOR`; closing it accepts the remaining changes, even
if you leave the diff unchanged. Empty the file to abort. A successful save prints
`Saved changes to <ghsa> on GitHub.` only after reloading the advisory and verifying its
editable fields. A mismatch or reload failure keeps your recovery files and reports the
problem. Changes only to comments or formatting do not count as a saved advisory change.
At the following prompt, enter `v` to view the current advisory, `r` to run another review
with fresh context, `b` to find similar bugs, or `e` to edit it. Press Enter alone to return
to the list and reload it.
If there are no changes, the review notes are shown without opening an empty diff.
Failed AI replies are displayed with their recovery path and do not update GitHub.

Press **`b`** (or choose **Find similar bugs** from `m`) to search for related mistakes.
The selected advisory, including its CVE and references, becomes the template. On a commit
or issue/PR, the search uses that source and includes its linked advisory when available;
an advisory is not required. The optional context can narrow the search, for example:
"Look for the same missing bounds check in related parsers and callers." Enter starts;
Escape or Ctrl+C cancels. It uses the same `GHAV_AI` agent as review.

The agent checks the root cause and fix, searches the current checkout for related bugs,
and reports locations, triggers, evidence, confidence and verification steps, separating
unverified leads from confirmed findings. Results open in the Markdown viewer and stay in
`reply.txt` in the printed recovery directory, alongside the source evidence and prompt.
`ghav resume <directory>` reopens the saved report without running the AI again. The
workflow does not create or update advisories. From the CLI:

```sh
ghav similar GHSA-xxxx-yyyy-zzzz check sibling parsers
ghav similar 8f3a2c1 look for other callers missing this check
```

Press **`C`** on an advisory (or choose it from `m`) to manage credits. You can also open
that screen directly with `ghav credits GHSA-xxxx-yyyy-zzzz`. Use `a` to add, `e` to edit,
`d` to delete, `?` to see all roles and `s` to save. Each entry pairs a GitHub username
with a role; the same person can have several roles. The picker explains finder,
reporter, analyst, coordinator, remediation developer/reviewer/verifier, tool, sponsor
and other. Saving updates only credits and does not run the AI. Unsaved edits stay in
the screen on API errors; `q`, Escape or Ctrl+C offers save/discard/cancel when needed.
See [credits controls](doc/tui.md#credits-screen).

The third tab lists issues and PRs labeled `cve` by default. To choose another label,
set `GHAV_LABEL` or pass the label to `tui`:

```sh
ghav -r owner/repo                     # includes the cve issues/PRs tab
ghav -r owner/repo issues              # cve issues/PRs without the TUI
ghav -r owner/repo tui "needs-cve"
GHAV_LABEL="needs-cve" ghav -r owner/repo
ghav -r owner/repo issues "needs-cve"    # the same list without the TUI
ghav new https://github.com/owner/repo/issues/123
ghav new https://github.com/owner/repo/pull/456 extra context about the fix
```

The label view includes open and closed issues/PRs, including merged PRs. Press `n` on an
item to prepare a draft, review it in `$EDITOR`, then `c` on its linked advisory to request
the CVE. `enter` shows the report and discussion. Links are recognized from issue/PR URLs
in advisory descriptions; existing advisories without those references will not be linked.
Labels stay unchanged. The positional label overrides `GHAV_LABEL`; when neither supplies
a nonempty label, both the TUI and `issues` use `cve`.

`new` accepts HTTPS `github.com` issue, PR and commit URLs, as well as commit hashes.
The URL supplies the repository when neither `-r` nor `GHAV_REPO` is set; an explicit
repository must match it. Issue drafts include the body and discussion; PR drafts also
include the patch and merge metadata. The agent investigates linked fixes and flags
unknown affected/patched versions for your review. Creating a draft does not request a CVE
or publish it.

CVE assignment is separate from publication. For an already published advisory:

```sh
ghav -r owner/repo cve GHSA-xxxx-yyyy-zzzz
ghav -r owner/repo status GHSA-xxxx-yyyy-zzzz
```

In the TUI and `ls`, `requested*` means GitHub accepted a request made through `ghav`.
The receipt survives restarts; `status` (or `s`) shows its acceptance time. Reload with
`g` to check for the assigned ID, which takes precedence over the receipt.
Receipts are stored per GitHub host, repository and advisory under
`${XDG_STATE_HOME:-$HOME/.local/state}/ghav/cve-requests/`.

This is a local record, not live queue progress: GitHub's documented
[REST](https://docs.github.com/en/rest/security-advisories/repository-advisories) and
[GraphQL](https://docs.github.com/en/graphql/reference/security-advisories) APIs do not
expose a pending-request status. Requests made elsewhere or before receipt tracking
cannot be recovered automatically; an unassigned CVE without a receipt has unknown
request status. To explicitly retry a request, use `ghav cve <ghsa>`.

Press `enter` on an advisory to render its Markdown with `r2 -q -c "cat -m file.md" --`
when `r2` is on `PATH`. Otherwise it opens in `$PAGER` (default: `less`). After closing
the viewer, the same `v`/`r`/`b`/`e` prompt lets you continue working on that advisory;
press Enter alone to return to the list. Every view and AI review fetches it from GitHub.

Agents: `claude -p` (default), `codex exec -`, `pmai "$(cat)"`, and
`opencode run "$(cat)"`. Press `A` in the TUI to cycle these presets, or set `GHAV_AI`
to any command that reads a prompt on stdin. The `pmai` and OpenCode presets pass
that input as a single quoted argument. For example:

```sh
GHAV_AI='opencode run "$(cat)"' ghav -r owner/repo
```

`new`, `edit` and `review` print a private recovery directory before editing or running
the agent. The AI reply, original advisory, proposed version, diff and saved edits stay
there on errors or aborts. If a review diff cannot be applied or parsed, choose to retry
the diff, take the full AI version, edit the result by hand, or quit and keep the files.
GitHub save errors also offer editing the saved result or using the proposed version.

Resume with `ghav resume <directory>`; it uses the saved repository and advisory and
does not run the AI again. In the TUI, Ctrl+C during the AI or a recovery prompt cancels
the operation and returns to the list; an interrupted editor also restores the terminal.
Standalone CLI workflows exit with status 130 on Ctrl+C. Both keep saved edits and any
output the agent has written so far. A partial reply may need repair in
`reply.txt` before resuming. Recovery files are removed only after GitHub confirms the
save. They live in the system temporary directory; copy the directory elsewhere to keep
it across system cleanup. See [recovery details](doc/advisory-format.md#recovery).

## Documentation

| Page | Content |
| --- | --- |
| [doc/usage.md](doc/usage.md) | every command and a typical end-to-end flow |
| [doc/tui.md](doc/tui.md) | views and all keybindings |
| [doc/advisory-format.md](doc/advisory-format.md) | the text format and the review diff rules |
| [doc/ai-agent.md](doc/ai-agent.md) | how the agent is prompted and what it checks |
| [doc/configuration.md](doc/configuration.md) | `GHAV_*`, `EDITOR`, `PAGER`, permissions |
| [doc/how-it-works.md](doc/how-it-works.md) | API endpoints and commit linking |
| [doc/design-notes.md](doc/design-notes.md) | why it works this way, and limitations |

See the repository for license terms.
