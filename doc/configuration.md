# Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `GHAV_REPO` | cwd checkout | repository, `owner/repo` |
| `GHAV_GREP` | `##(crash\|security)` | `git log -E --grep` pattern for fix commits |
| `GHAV_LABEL` | unset | label for the optional issues/PRs tab and `issues` command; includes open and closed items |
| `GHAV_AI` | `claude -p` | agent command, prompt on stdin |
| `EDITOR` | `vi` | editor for drafts and reviews |
| `PAGER` | `less` | advisory and issue/PR viewer when `r2` is not on `PATH` |

`-r owner/repo` overrides `GHAV_REPO`.
For `new <url>`, the URL supplies the repository before the cwd checkout is consulted;
it must match an explicit `-r` or `GHAV_REPO`. `tui <label>` and `issues <label>` override
`GHAV_LABEL`. Quote labels containing spaces.

When `r2` is on `PATH`, the TUI uses `r2 -q -c "cat -m file.md" --` to render
advisory and issue/PR Markdown. Press `enter` after reading to return to the list.

## Permissions

`gh` must be authenticated with **Repository security advisories: write** permission, plus
repo admin or security-manager access.
