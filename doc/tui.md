# TUI

Running `ghav` with no command opens the TUI.

```sh
cd ~/radare2
ghav
```

Two views, switched with `tab`:

| View | Shows |
| --- | --- |
| advisories | GHSA id, state, CVE id, severity, summary |
| commits | tagged fix commits (`GHAV_GREP`), date, subject, and the advisory referencing them |

Keys:

| Key | Action |
| --- | --- |
| `j` / `k` | move one row |
| mouse wheel down / up | move one row, like `j` / `k` |
| `J` / `K` | move ten rows |
| `tab` | switch view, and jump to the linked commit/advisory |
| `enter` | show the commit (`git show`) or the advisory (`r2` Markdown rendering if available, otherwise `$PAGER`) |
| `n` | draft an advisory for the selected commit |
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
| `g` | reload both lists |
| `?` | show all keys and the active AI agent |
| `q` | quit |

In the commit view, advisory actions act on the advisory that references the
selected commit. If there is none, the status line tells you to press `n`.

The bottom two rows separate colored keys from descriptions. The action row and `m` menu
offer actions appropriate to the selected advisory's state and CVE assignment. The status
line above them shows the selection or the result of the last action. All lifecycle and
CVE actions require confirmation; errors leave the advisory unchanged locally.

Published advisories without a CVE offer `c request CVE`. On success, the list shows
`requested*`, meaning GitHub accepted a request during this session. This is a local
acknowledgement, not a new advisory state or an API-reported pending status. Press `g`
to refresh the assigned CVE; `s` displays the latest server details. Repeat requests are
suppressed for the rest of the session, and assigned IDs replace the marker on refresh.

The state filter applies only to the advisory list; commit links still use all advisories.
Jumping from a commit to a linked advisory outside the current filter switches back to all.

After viewing an advisory with `r2`, press `enter` to return to the list.

Mouse reporting is enabled while the TUI is active, so the wheel moves the selection
instead of the terminal scrollback. It is disabled when opening a viewer, editor or
prompt in cooked mode, and when quitting.

The header shows the repository, active view and advisory filter. Pressing `A`
cycles through `claude -p`, `codex exec -` and `pmai "$(cat)"`; a custom `GHAV_AI` is
replaced by the first preset. The selected agent appears in the status line and `?` help.
