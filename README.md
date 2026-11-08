# ghav

**GitHub security advisories from the command line, written in [V](https://vlang.io).**

Turn a fix commit into a published security advisory — with your AI agent doing the
reconstruction and you keeping the last word.

```
$ cd ~/radare2
$ ghav new 8f3a2c1 found by fuzzing the PDB parser

  [claude] reading the patch, checking tags and history...
  severity: high  cwe: CWE-787  affected: >= 4.5.1, < 6.2.2  patched: 6.2.2
  → opening $EDITOR... saved as draft GHSA-xxxx-yyyy-zzzz
```

## What it does

- **Lists** your repo's advisories and the local commits that look like fixes (`##crash`, `##security`).
- **Drafts** an advisory from a single commit: the agent reads the patch, the history and the
  tags, and writes root cause, CWE, CVSS and the affected/patched versions.
- **Reviews** existing advisories with the agent as a diff you accept or reject line by line.
- **Assigns CVEs, publishes and closes** — always behind an explicit confirmation.
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

## Usage

```
ghav [-r owner/repo] [command] [args]

  tui                     interactive list (default)
  ls                      list advisories
  log                     list fix commits and their advisories
  new <commit> [context]  analyze a commit with AI and create a draft
  show <ghsa>             print an advisory
  edit <ghsa>             edit an advisory in $EDITOR
  review <ghsa> [context] AI-review and rewrite it, then edit
  approve <ghsa>          request a CVE id
  publish <ghsa>          publish
  close <ghsa>            close (reject)
```

Run `ghav` with no arguments for the TUI: advisories and fix commits side by side, `tab` to
switch, `n` to draft, `r` to review, `p` to publish.

Press `enter` on an advisory to render its Markdown with `r2 -q -c "cat -m file.md" --`
when `r2` is on `PATH`, then press `enter` to return. Otherwise it opens in `$PAGER`
(default: `less`).

Agents: `claude -p` (default), `codex exec -`, `pmai` — anything that reads a prompt on
stdin.

## Documentation

| Page | Content |
| --- | --- |
| [doc/usage.md](doc/usage.md) | every command and a typical end-to-end flow |
| [doc/tui.md](doc/tui.md) | both views and all keybindings |
| [doc/advisory-format.md](doc/advisory-format.md) | the text format and the review diff rules |
| [doc/ai-agent.md](doc/ai-agent.md) | how the agent is prompted and what it checks |
| [doc/configuration.md](doc/configuration.md) | `GHAV_*`, `EDITOR`, `PAGER`, permissions |
| [doc/how-it-works.md](doc/how-it-works.md) | API endpoints and commit linking |
| [doc/design-notes.md](doc/design-notes.md) | why it works this way, and limitations |

See the repository for license terms.
