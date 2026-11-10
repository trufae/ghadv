# Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `GHADV_REPO` | cwd checkout | project path (`owner/repo` or `group/subgroup/repo`) or full repository URL |
| `GHADV_PROVIDER` | detect from URL/remote | `github` or `gitlab`; required for custom hosts |
| `GHADV_HOST` | URL/remote host | API server hostname, optionally with HTTPS port |
| `GHADV_REMOTE` | upstream, origin, sole remote | select a Git remote explicitly |
| `GHADV_ADVISORY_LABEL` | `security-advisory` | GitLab disclosure issue label for `ls`, the disclosures tab and `new` |
| `GHADV_GREP` | `##(crash\|security\|vulnerability\|sandbox)` | `git log -E --grep` pattern for fix commits |
| `GHADV_LABEL` | `cve` | label for the issues/PRs/MRs tab and `issues` command; includes open and closed items |
| `GHADV_AI` | `claude -p` | agent command, prompt on stdin |
| `EDITOR` | `vi` | editor for drafts and reviews |
| `PAGER` | `less` | advisory and issue/PR viewer when `r2` is not on `PATH` |
| `XDG_STATE_HOME` | `~/.local/state` | base directory for persistent CVE request records and invalid tags |

`-r`, `--provider`, `--host` and `--remote` override the corresponding `GHADV_*` setting.
Put them before the command. See [repository selection](gitlab.md#setup-and-repository-selection).
For `new <url>` (also `similar`, `invalid` and `unmark`), the URL supplies the repository before the cwd checkout is consulted;
it must match an explicit `-r` or `GHADV_REPO`. `tui <label>` and `issues <label>` override
`GHADV_LABEL`. An unset or empty `GHADV_LABEL` defaults to `cve`. Quote labels containing spaces.

When no repository/source URL is supplied and `GHADV_HOST` is unset, `GH_HOST` supplies
the GitHub host; with `--provider gitlab`, `GITLAB_HOST` supplies the GitLab host.
An inherited `GH_HOST` also selects GitHub when no provider is set, preserving existing
GitHub configuration. Other custom hosts require a provider. Explicit URLs do not
inherit these CLI-specific host defaults. Each API request receives the resolved hostname explicitly.

When `r2` is on `PATH`, the TUI uses `r2 -q -c "cat -m file.md" --` to render
advisory and issue/PR Markdown. Press `enter` after reading to return to the list.

## Local CVE request records

After GitHub accepts a CVE request, ghadv saves its UTC timestamp in
`$XDG_STATE_HOME/ghadv/cve-requests/`, or `~/.local/state/ghadv/cve-requests/` by default.
Each file is named with a hash of the resolved GitHub host,
repository and advisory ID. These records are shared by the CLI and TUI and survive
closing the app, restarting it, or switching checkouts of the same repository.

The list shows `requested*` while a recorded request has no assigned CVE;
`ghadv status <ghsa>` shows when the request was accepted. An assigned CVE takes
precedence over the local record. Requests made through the GitHub website or raw
`gh` commands do not create these local records.

## Local invalid tags

Invalid tags and their reasons are JSON files below `$XDG_STATE_HOME/ghadv/invalid/`,
or `~/.local/state/ghadv/invalid/` by default. The resolved host and repository scope the directory;
GitLab includes an additional provider prefix in the hash to avoid collisions. Existing
GitHub record paths are preserved; a hash of the advisory ID, full commit SHA or
issue/PR URL identifies each record. IDs and URLs are compared without case sensitivity.
Tags are shared by the CLI and TUI and by checkouts of the same repository on this machine.
They are not uploaded to GitHub or GitLab. GitLab disclosure IDs (`GL-123`) and their
issue URLs share a tag. `ghadv unmark <ghsa|commit|url>` removes a record.

## Permissions

`gh` must be authenticated with **Repository security advisories: write** permission, plus
repo admin or security-manager access for the relevant GitHub operations. For GitLab,
use an authenticated `glab` account with permission to read/create/edit the project
issues. Requesting a CVE through GitLab's website requires Maintainer/Owner access
to an eligible public GitLab.com project. See [the GitLab guide](gitlab.md).
