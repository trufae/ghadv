# TUI

Running `ghav` with no command opens the TUI.

```sh
cd ~/radare2
ghav
```

Views, switched with `tab`:

| View | Shows |
| --- | --- |
| advisories | GHSA id, state, CVE id, severity, summary |
| commits | tagged fix commits (`GHAV_GREP`), date, subject, and the advisory referencing them |
| issues/PRs | items with `GHAV_LABEL` (or `ghav tui <label>`), number, type, state, linked advisory and title |

The issues/PRs tab appears only when a label is configured. It includes every state, so
closed issues and merged PRs remain available for reporting. `closed` in this list can
mean either a merged or a closed, unmerged PR; `enter` shows its merge metadata.

Keys:

| Key | Action |
| --- | --- |
| `j` / `k` | move one row |
| mouse wheel down / up | move one row, like `j` / `k` |
| `J` / `K` | move ten rows |
| `tab` | cycle views, selecting a linked entry in the next view when one exists |
| `enter` | show the commit (`git show`), advisory or issue/PR discussion (`r2` Markdown rendering if available, otherwise `$PAGER`) |
| `n` | draft from the selected commit or issue/PR; in the advisory view, prompt for a commit or URL and optional context |
| `e` | edit the linked advisory |
| `r` | AI-review the linked advisory |
| `m` | open the selected advisory's actions menu |
| `c` / `a` | request a CVE, including for a published advisory |
| `d` | accept a triage report or reopen a closed advisory as draft |
| `p` | publish |
| `x` | close (asks `[y/N]`) |
| `s` | show lifecycle, CVE, private-report status, timestamps and URL |
| `f` | cycle all / triage / draft / published / closed |
| `A` | cycle the AI agent preset |
| `g` | reload all lists |
| `?` | show all keys and the active AI agent |
| `q` | quit |

In the commit and issues/PRs views, advisory actions act on the advisory that references
the selected item. If there is none, press `n` to prepare a draft, review it in `$EDITOR`,
then `c` to request a CVE. Issue/PR links require their full URL in the advisory description.
Creating a draft does not request a CVE, publish, or remove the label.

The bottom two rows separate colored keys from descriptions. The action row and `m` menu
offer actions appropriate to the selected advisory's state and CVE assignment. The status
line above them shows the selection or the result of the last action. All lifecycle and
CVE actions require confirmation; errors leave the advisory unchanged locally.

Published advisories without a CVE offer `c request CVE`. On success, the list shows
`requested*`, meaning GitHub accepted a request during this session. This is a local
acknowledgement, not a new advisory state or an API-reported pending status. Press `g`
to refresh the assigned CVE; `s` displays the latest server details. Repeat requests are
suppressed for the rest of the session, and assigned IDs replace the marker on refresh.

The state filter applies only to the advisory list; source links still use all advisories.
Jumping to a linked advisory outside the current filter switches back to all.

After viewing an advisory with `r2`, press `enter` to return to the list.

Mouse reporting is enabled while the TUI is active, so the wheel moves the selection
instead of the terminal scrollback. It is disabled when opening a viewer, editor or
prompt in cooked mode, and when quitting.

The header shows the repository, active view and advisory filter. Pressing `A`
cycles through `claude -p`, `codex exec -` and `pmai "$(cat)"`; a custom `GHAV_AI` is
replaced by the first preset. The selected agent appears in the status line and `?` help.
