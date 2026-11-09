# Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `GHADV_REPO` | cwd checkout | repository, `owner/repo` |
| `GHADV_GREP` | `##(crash\|security)` | `git log -E --grep` pattern for fix commits |
| `GHADV_LABEL` | `cve` | label for the issues/PRs tab and `issues` command; includes open and closed items |
| `GHADV_AI` | `claude -p` | agent command, prompt on stdin |
| `EDITOR` | `vi` | editor for drafts and reviews |
| `PAGER` | `less` | advisory and issue/PR viewer when `r2` is not on `PATH` |

`-r owner/repo` overrides `GHADV_REPO`.
For `new <url>`, the URL supplies the repository before the cwd checkout is consulted;
it must match an explicit `-r` or `GHADV_REPO`. `tui <label>` and `issues <label>` override
`GHADV_LABEL`. An unset or empty `GHADV_LABEL` defaults to `cve`. Quote labels containing spaces.

When `r2` is on `PATH`, the TUI uses `r2 -q -c "cat -m file.md" --` to render
advisory and issue/PR Markdown. Press `enter` after reading to return to the list.

## Permissions

`gh` must be authenticated with **Repository security advisories: write** permission, plus
repo admin or security-manager access.
