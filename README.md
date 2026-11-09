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
make install          # builds and installs ghav into ~/.local/bin
```

Or build only: `make` (same as `v -o ghav ghadv.v`). `PREFIX` and `BINDIR` are overridable;
`make uninstall` and `make clean` exist too.

Run the focused URL parsing and advisory-link tests with `v test ghadv_test.v`.

## Usage

```
ghav [-r owner/repo] [command] [args]

  tui [label]             interactive list (default), optionally with issues/PRs
  ls [state]              list all/triage/draft/published/closed advisories
  log                     list fix commits and their advisories
  issues [label]          list labeled issues/PRs (default: GHAV_LABEL)
  new <commit|url> [context] analyze a commit, issue or PR with AI and create a draft
  show <ghsa>             print an advisory
  status <ghsa>           show lifecycle, CVE and private report details
  edit <ghsa>             edit an advisory in $EDITOR
  review <ghsa> [context] AI-review and rewrite it, then edit
  cve <ghsa>              request a CVE id (asynchronous)
  approve <ghsa>          alias for cve
  draft <ghsa>            accept a report or reopen as a draft
  publish <ghsa>          publish
  close <ghsa>            close (reject)
```

Run `ghav` with no arguments for the TUI: advisory and fix-commit views, `tab` to
switch, `m` for the selected advisory's actions, `c` to request a CVE, `s` for status,
and `f` to filter by state. Two rows of colored shortcuts show navigation and the actions
available for the selection; `?` shows all keys. Use `j`/`k` or the mouse wheel to
move down/up one row in the active list.

To load your CVE label as a third tab, set `GHAV_LABEL` or pass the label to `tui`:

```sh
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
Labels stay unchanged. The positional label overrides `GHAV_LABEL`; without a label the
TUI keeps its two original views.

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

In the TUI, `requested*` records a CVE request accepted during this session. Reload with
`g` to check for the assigned ID; GitHub REST does not expose a pending-request status.

Press `enter` on an advisory to render its Markdown with `r2 -q -c "cat -m file.md" --`
when `r2` is on `PATH`, then press `enter` to return. Otherwise it opens in `$PAGER`
(default: `less`).

Agents: `claude -p` (default), `codex exec -`, `pmai` — anything that reads a prompt on
stdin.

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
