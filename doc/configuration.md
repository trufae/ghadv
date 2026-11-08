# Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `GHAV_REPO` | cwd checkout | repository, `owner/repo` |
| `GHAV_GREP` | `##(crash\|security)` | `git log -E --grep` pattern for fix commits |
| `GHAV_AI` | `claude -p` | agent command, prompt on stdin |
| `EDITOR` | `vi` | editor for drafts and reviews |
| `PAGER` | `less` | viewer for `enter` on an advisory |

`-r owner/repo` overrides `GHAV_REPO`.

## Permissions

`gh` must be authenticated with **Repository security advisories: write** permission, plus
repo admin or security-manager access.
