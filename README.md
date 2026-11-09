# ghav

Manage GitHub security advisories from the command line. Written in [V](https://vlang.io).

Turn a fix commit, issue or pull request into a published advisory — an AI agent does the
reconstruction, you keep the last word.

```sh
$ cd ~/radare2
$ ghav new 8f3a2c1 found by fuzzing the PDB parser
```

## What it does

- Lists advisories, local fix commits, and labeled issues/PRs.
- Drafts an advisory from a commit or GitHub issue/PR URL: the agent reads the report,
  discussion, patch, history and tags, then writes root cause, CWE, CVSS and versions.
- Reviews existing advisories with the agent as a diff you accept or reject line by line.
- Finds similar bugs using an advisory, CVE or fix commit as a template for an AI search.
- Manages credits (finders, reporters, fix authors, ...) in a TUI screen.
- Requests CVEs, accepts private reports, publishes and closes advisories. TUI actions confirm.

Advisories are plain text in `$EDITOR` — no JSON, no web forms.

## Install

Requires [V](https://vlang.io), `git`, and an authenticated `gh` with
**Repository security advisories: write** permission.

```sh
git clone <this repo> && cd ghav
make BIN=ghav install   # builds and installs ghav into ~/.local/bin
```

Or build only: `make` (defaults to `ghadv`), or `v -o ghav .`. `BIN`, `PREFIX` and
`BINDIR` are overridable; `make uninstall` and `make clean` exist. Use the same `BIN`
value for install, uninstall and clean.

## Usage

```sh
ghav [-r owner/repo] [command] [args]
```

Run `ghav` with no arguments for the TUI (advisory, commit and labeled issues/PRs tabs).
Use `Tab` to cycle tabs forward and `Shift-Tab` to cycle backward, wrapping at either end.
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

Configuration lives in `GHAV_REPO`, `GHAV_LABEL`, `GHAV_AI`, `GHAV_GREP`, plus `$EDITOR`
and `$PAGER`. See [doc/configuration.md](doc/configuration.md).

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
