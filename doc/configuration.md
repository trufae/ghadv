# Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `GHADV_REPO` | cwd checkout | repository, `owner/repo` |
| `GHADV_GREP` | `##(crash\|security\|vulnerability\|sandbox)` | `git log -E --grep` pattern for fix commits |
| `GHADV_LABEL` | `cve` | label for the issues/PRs tab and `issues` command; includes open and closed items |
| `GHADV_AI` | `claude -p` | agent command, prompt on stdin |
| `EDITOR` | `vi` | editor for drafts and reviews |
| `PAGER` | `less` | advisory and issue/PR viewer when `r2` is not on `PATH` |
| `XDG_STATE_HOME` | `~/.local/state` | base directory for persistent CVE request records |

`-r owner/repo` overrides `GHADV_REPO`.
For `new <url>`, the URL supplies the repository before the cwd checkout is consulted;
it must match an explicit `-r` or `GHADV_REPO`. `tui <label>` and `issues <label>` override
`GHADV_LABEL`. An unset or empty `GHADV_LABEL` defaults to `cve`. Quote labels containing spaces.

When `r2` is on `PATH`, the TUI uses `r2 -q -c "cat -m file.md" --` to render
advisory and issue/PR Markdown. Press `enter` after reading to return to the list.

## Local CVE request records

After GitHub accepts a CVE request, ghadv saves its UTC timestamp in
`$XDG_STATE_HOME/ghadv/cve-requests/`, or `~/.local/state/ghadv/cve-requests/` by default.
Each file is named with a hash of the GitHub host (`GH_HOST`, default `github.com`),
repository and advisory ID. These records are shared by the CLI and TUI and survive
closing the app, restarting it, or switching checkouts of the same repository.

The list shows `requested*` while a recorded request has no assigned CVE;
`ghadv status <ghsa>` shows when the request was accepted. An assigned CVE takes
precedence over the local record. Requests made through the GitHub website or raw
`gh` commands do not create these local records.

## Permissions

`gh` must be authenticated with **Repository security advisories: write** permission, plus
repo admin or security-manager access.
