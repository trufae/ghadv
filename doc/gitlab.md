# GitLab support

gsadv supports GitLab.com and explicitly configured self-managed GitLab servers through
the authenticated `glab` CLI. The default workflow uses ordinary confidential issues,
so it works without GitLab Ultimate. It does not query GitLab's vulnerability report or
publish records to the GitLab advisory database.

## Setup and repository selection

Install a version of `glab` supporting `api --paginate --output ndjson` (tested with
1.122.0), then authenticate with `glab auth login`. Only the CLI for the selected provider
is needed: `glab` for GitLab, `gh` for GitHub. gsadv passes argument arrays to these tools
and uses their authentication; it does not store another API token.

```sh
cd ~/my-gitlab-project
gsadv                         # detect the repository and open the TUI
gsadv ls                      # list disclosure issues
gsadv issues                  # issues and MRs labeled cve, including closed/merged items
gsadv --remote upstream ls    # use a particular remote

# Work outside a checkout, or select another project:
gsadv -r https://gitlab.com/group/subgroup/project ls
gsadv --provider gitlab -r group/subgroup/project ls

# Custom server; authenticate glab for this hostname first:
gsadv --provider gitlab -r https://code.example/group/project ls
```

Global options go before the command. `-r`, `--provider`, `--host` and `--remote` override
`GSADV_REPO`, `GSADV_PROVIDER`, `GSADV_HOST` and `GSADV_REMOTE`, respectively.

A source URL for `new`, `similar`, `invalid` or `unmark` selects the repository before
the checkout is consulted. It must match an explicit repository, provider and host.
Otherwise, the selected remote is the explicit `--remote`, the current branch's upstream
remote, `origin`, or a sole remaining remote, in that order. Multiple remaining remotes
require a choice. Remote detection uses local Git configuration, not an authentication
attempt. Authentication failures never trigger a switch to another provider.

HTTPS, `git@host:namespace/project.git` and `ssh://git@host/namespace/project.git` remotes
are supported, including nested GitLab subgroups. `github.com` and `gitlab.com` identify
their provider automatically. Other hosts require `--provider` or `GSADV_PROVIDER`.
Existing `GH_HOST` configuration also identifies a GitHub server when selecting a bare
project path or checkout; explicit source/repository URLs do not inherit that default.
For a custom HTTPS port, supply a full URL such as `https://code.example:8443/group/project`;
an SSH remote's port is not used as the API port. SSH host aliases are not expanded.

An explicit bare project path inherits the detected checkout's provider/host unless
provider/host options are supplied. Outside a checkout, a bare path defaults to GitHub
for compatibility; select GitLab explicitly or use a URL.

## Disclosure issues

The GitLab **disclosures** tab and `ls` select issues labeled `security-advisory`.
`GSADV_ADVISORY_LABEL` changes this label. The separate **issues/MRs** tab uses
`GSADV_LABEL` (default `cve`), or the label passed to `tui`/`issues`.

```sh
gsadv new https://gitlab.com/group/project/-/issues/12 "Check affected release tags"
# AI analysis -> editor -> a new confidential issue, for example GL-34
gsadv show GL-34
gsadv review GL-34 "Confirm the first affected and first fixed release"
gsadv edit GL-34
gsadv status GL-34
gsadv cve GL-34                # instructions only; no CVE request is submitted
gsadv close GL-34              # asks for confirmation
gsadv reopen GL-34             # asks for confirmation
```

`GL-34` is gsadv's notation for issue IID 34 in the selected project. It is neither a
GitLab vulnerability ID nor a CVE ID. Issues and MRs have separate number spaces: their
full URLs distinguish them. Source URLs support `/-/issues/34`, `/-/merge_requests/34`
and `/-/commit/<sha>`. MR evidence includes merge metadata, notes and paginated diffs.
Diffs omitted by GitLab or truncated by gsadv are identified in the evidence.

`new` creates an issue with `confidential=true` and the disclosure label. Existing
labeled issues also appear in the disclosure list, including ordinary Markdown reports
not created with gsadv. Their title and description are preserved when opened for editing.

The editor uses the existing [advisory format](advisory-format.md). GitLab stores its
metadata in a fenced text block preceded by `<!-- ghadv:advisory -->`, followed by the
Markdown description. The issue title is authoritative. CWE, CVSS, versions and credits
are text in the issue, not native GitLab security fields. Edit attribution with `e` or
`edit`; the structured GitHub credits screen is unavailable. Damaged gsadv metadata is
reported instead of silently discarded.

Saving an edit updates only the title and description, then reloads and compares the
editable fields. It preserves labels, state and confidentiality. Recovery sessions store
the provider, host, project, disclosure label and ID, so `resume` still targets the same
server after changing checkouts or configuration. Older GitHub recovery sessions remain
supported.

## State, visibility and CVE references

| Operation | GitHub | GitLab |
| --- | --- | --- |
| `ls` filters | all, triage, draft, published, closed | all, opened, closed |
| `new` | draft repository advisory | confidential disclosure issue |
| `close` / `x` | close an unpublished advisory/report | close the issue, preserving visibility |
| `reopen` / `d` | reopen as draft | reopen the issue, preserving visibility |
| `draft`, `publish` | native advisory transitions | unsupported |
| `cve` / `c` | submit a CVE request | show instructions for GitLab's separate request workflow |
| `credits` / `C` | structured advisory credits | maintain attribution in the report text |
| `invalid`, `unmark`, `i` / `I` | local tags | local tags |

GitLab rows and status show confidentiality separately from open/closed state. A closed
issue can still be confidential, and a public issue is not necessarily a published CVE.
Changing visibility must be done explicitly on GitLab; it affects access to the issue
and its discussion. gsadv does not make an issue public through `publish`, editing,
closing or reopening.

The CVE column lists unique uppercase `CVE-YYYY-number` references found in the issue
title and description. These are references, not confirmation of assignment or publication.
Record a newly assigned CVE in the description with `edit`.

GitLab's documented [CVE request workflow](https://docs.gitlab.com/user/application_security/cve_id_request/)
is available on all tiers for public projects on GitLab.com. It requires a Maintainer or
Owner and a confidential source issue. The **Create CVE ID Request** action opens a new
request in GitLab's CVE project. `gsadv cve GL-34` shows this procedure and the source
issue URL; it does not check eligibility, submit the request or create a local accepted
request receipt. Self-managed instances need the appropriate external CNA workflow.

Local invalid tags never change GitLab labels or issue state. `GL-34` and its canonical
issue URL identify the same local tag; a related commit or MR has its own tag. You can
use an ordinary GitLab `invalid` label and explanation upstream separately.

## Other GitLab security features

GitLab's [confidential issues](https://docs.gitlab.com/user/project/issues/confidential_issues/)
are available on Free, Premium and Ultimate. They are the basis of this integration.

The [vulnerability report](https://docs.gitlab.com/user/application_security/vulnerability_report/)
is a different feature requiring Ultimate. It contains security findings with triage,
confirmed, dismissed and resolved states, including dismissal reasons and comments.
Those records can include dependency vulnerabilities and are not equivalent to a project's
own disclosure issues. A future integration should keep them distinct and use GraphQL:
GitLab documents the [vulnerability REST API](https://docs.gitlab.com/api/vulnerabilities/)
as unstable and being deprecated. gsadv currently does not read or modify these records.

The [GitLab advisory database](https://docs.gitlab.com/user/application_security/gitlab_advisory_database/)
aggregates dependency advisories from sources including NVD and GHSA. Creating an issue
with gsadv does not add a database entry or publish a CVE.

## Offline validation

```sh
build_dir=$(mktemp -d)
v -o "$build_dir/gsadv" .
v test .
python3 test/gitlab_smoke.py "$build_dir/gsadv"
```

The smoke test puts stub `gh`, `glab` and AI executables on `PATH`. It checks source
evidence, payloads, visibility preservation, recovery, provider selection, local tags,
GitHub CVE receipts and, on POSIX systems, interactive TUI navigation and actions.
It does not access GitHub or GitLab accounts.
