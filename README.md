# ghadv

Manage GitHub security advisories from the command line. Written in [V](https://vlang.io).

Turn a fix commit, issue or pull request into a published advisory — an AI agent does the
reconstruction, you keep the last word.

```sh
$ cd ~/radare2
$ ghadv new 8f3a2c1 found by fuzzing the PDB parser
```

## What it does

- Lists advisories, local fix commits, and labeled issues/PRs.
- Drafts an advisory from a commit or GitHub issue/PR URL: the agent reads the report,
  discussion, patch, history and tags, then writes root cause, CWE, CVSS and versions.
  Finder/reporter attribution and scan IDs are preserved in credits or the advisory text.
- Reviews existing advisories with the agent as a diff you accept or reject line by line.
- Finds similar bugs using an advisory, CVE or fix commit as a template for an AI search.
- Manages credits (finders, reporters, fix authors, ...) in a TUI screen.
- Requests CVEs, accepts private reports, publishes and closes advisories. TUI actions confirm.
- Saves accepted CVE requests locally, preserving `requested*` across restarts until a CVE is assigned.

Advisories are plain text in `$EDITOR` — no JSON, no web forms.

## Install

Requires [V](https://vlang.io), `git`, and an authenticated `gh` with
**Repository security advisories: write** permission.

```sh
git clone <this repo> && cd ghadv
make BIN=ghadv install   # builds and installs ghadv into ~/.local/bin
```

Or build only: `make` (defaults to `ghadv`), or `v -o ghadv .`. `BIN`, `PREFIX` and
`BINDIR` are overridable; `make uninstall` and `make clean` exist. Use the same `BIN`
value for install, uninstall and clean.

## Usage

```sh
ghadv [-r owner/repo] [command] [args]
```

Run `ghadv` with no arguments for the TUI (advisory, commit and labeled issues/PRs tabs).
The screen opens immediately while repository detection, GitHub lists and local Git
details load in background threads. Each tab becomes usable as its data arrives;
navigation and quitting stay responsive during loading and reloads. Reload failures
keep the previous list. Searches, advisory links and formatted rows are cached, so
moving the selection does not rescan the lists or reformat unchanged rows.
Use `Tab` to cycle tabs forward and `Shift-Tab` to cycle backward, wrapping at either end.
Tabs occupy their own second row, with the active tab highlighted in inverse colors.
The top row shows the repository and local checkout's
latest commit (hash and subject), plus clean, unstaged, staged, untracked or conflicted
status. Git details refresh with `g` and after returning from a viewer, editor or AI workflow.
The TUI adapts to narrow and short terminals, keeps the selection visible when resized,
and refreshes changed rows without clearing the screen. Small widths use compact rows;
open an entry to read its full text. Menus and help scroll with `j`/`k` or the mouse wheel.
Key commands:

| Command | What |
| --- | --- |
| `tui [label]` | interactive TUI (default) |
| `ls [state]` | list advisories |
| `log` | list fix commits and their advisories |
| `issues [label]` | list labeled issues/PRs |
| `new <commit\|url> [context]` | analyze and create a draft |
| `show <ghsa>` | print an advisory |
| `status <ghsa>` | lifecycle, CVE and report details |
| `credits <ghsa>` | manage credits in the TUI |
| `edit <ghsa>` | edit in `$EDITOR` |
| `review <ghsa> [context]` | AI review, then edit |
| `similar <ghsa\|commit\|url> [context]` | find similar bugs |
| `resume <dir>` | continue saved work |
| `cve <ghsa>` | request a CVE id |
| `draft/publish/close <ghsa>` | change state |

Configuration lives in `GHADV_REPO`, `GHADV_LABEL`, `GHADV_AI`, `GHADV_GREP`, plus `$EDITOR`
and `$PAGER`. See [doc/configuration.md](doc/configuration.md).

## Documentation

| Page | Content |
| --- | --- |
| [doc/usage.md](doc/usage.md) | every command and a typical end-to-end flow |
| [doc/tui.md](doc/tui.md) | views and all keybindings |
| [doc/advisory-format.md](doc/advisory-format.md) | the text format and the review diff rules |
| [doc/ai-agent.md](doc/ai-agent.md) | how the agent is prompted and what it checks |
| [doc/configuration.md](doc/configuration.md) | `GHADV_*`, `EDITOR`, `PAGER`, permissions |
| [doc/how-it-works.md](doc/how-it-works.md) | API endpoints and commit linking |
| [doc/design-notes.md](doc/design-notes.md) | why it works this way, and limitations |

See the repository for license terms.
