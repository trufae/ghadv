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
| `J` / `K` | move ten rows |
| `tab` | switch view, and jump to the linked commit/advisory |
| `enter` | show the commit (`git show`) or the advisory (`r2` Markdown rendering if available, otherwise `$PAGER`) |
| `n` | draft an advisory for the selected commit |
| `e` | edit the linked advisory |
| `r` | AI-review the linked advisory |
| `a` | request the CVE id |
| `p` | publish |
| `x` | close (asks `[y/N]`) |
| `A` | cycle the AI agent preset |
| `g` | reload both lists |
| `q` | quit |

In the commit view, `e`, `r`, `a`, `p` and `x` act on the advisory that references the
selected commit. If there is none, the status line tells you to press `n`.

After viewing an advisory with `r2`, press `enter` to return to the list.

The header shows the current repository and the active `GHAV_AI` command. Pressing `A`
cycles through `claude -p`, `codex exec -` and `pmai "$(cat)"`; a custom `GHAV_AI` is
replaced by the first preset.
