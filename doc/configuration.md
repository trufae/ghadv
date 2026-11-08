# Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `GHAV_REPO` | cwd checkout | repository, `owner/repo` |
| `GHAV_GREP` | `##(crash\|security)` | `git log -E --grep` pattern for fix commits |
| `GHAV_AI` | `claude -p` | agent command, prompt on stdin |
| `EDITOR` | `vi` | editor for drafts and reviews |
| `PAGER` | `less` | advisory viewer when `r2` is not on `PATH` |

`-r owner/repo` overrides `GHAV_REPO`.

When `r2` is on `PATH`, the TUI uses `r2 -q -c "cat -m file.md" --` to render
advisory Markdown. Press `enter` after reading to return to the list.

## Permissions

`gh` must be authenticated with **Repository security advisories: write** permission, plus
repo admin or security-manager access.
