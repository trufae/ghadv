# Usage

`gsadv` is a CLI with an interactive TUI mode on top of it. GitHub uses native repository
advisories; GitLab uses labeled disclosure issues. See [GitLab support](gitlab.md) for
its workflow and platform differences. `<id>` means `GHSA-…` on GitHub or `GL-123` on GitLab.

```
gsadv [-r namespace/repo|url] [--provider github|gitlab] [--host hostname] [--remote name] [command] [args]
  --version, -v, version   print the tool version
  tui [label]              advisory, commit and labeled issues/PRs tabs (default)
  ls [state]               GitHub advisories or GitLab disclosure issues (opened/closed)
  log                     list tagged fix commits and their advisories
  issues [label]           list labeled issues/PRs (default: GSADV_LABEL or cve)
  new <commit|url> [context] analyze a commit, issue or PR/MR with AI and create a draft
  show <id>               print advisory
  status <id>             show lifecycle, CVE and private report details
  credits <id>            manage credited people and roles in the TUI
  edit <id>               edit advisory in $EDITOR
  review <id> [context]   let the AI review/rewrite it, then edit
  similar <id|commit|url> [context] find similar bugs using the selection as a template
  resume <directory>       continue saved work without running the AI again
  cve <id>                 GitHub: request CVE; GitLab: show CVE request instructions
  approve <id>            alias for cve
  draft <id>              accept a report or reopen as a draft
  publish <id>            publish the advisory
  close <id>               close the advisory/disclosure
  reopen <id>              reopen a closed advisory/disclosure
  invalid <id|commit|url> [reason] show its local tag, or mark invalid with a reason
  unmark <id|commit|url>  remove its local invalid tag
GitLab disclosure IDs use GL-<issue number>; publish/draft/credits are GitHub-only.
```

`-h`, `--help` or `help` prints command help. Global options go before the command.
`draft`, `publish` and structured `credits` are GitHub-only.

## Repository

A repository/source URL identifies its host and project; explicit settings must agree.
For a checkout, detection selects `--remote`, the current branch's upstream remote,
`origin`, or a sole remaining remote. Unknown custom hosts require `--provider`.
`-r` overrides `GSADV_REPO`; a bare project path uses the selected provider/host or
inherits the checkout's identity. Outside a checkout, a bare path defaults to GitHub.
A GitLab source URL can also select the repository without `-r`.

See [repository selection and custom hosts](gitlab.md#setup-and-repository-selection)
for complete examples and the `GSADV_*` overrides.

## Typical flow

```sh
cd ~/radare2
gsadv new 8f3a2c1 found by fuzzing PDB files   # AI analysis -> $EDITOR -> draft
gsadv review GHSA-xxxx-yyyy-zzzz               # AI review as a diff -> $EDITOR
gsadv cve GHSA-xxxx-yyyy-zzzz                  # request the CVE id (async)
gsadv status GHSA-xxxx-yyyy-zzzz               # check assignment and lifecycle
gsadv publish GHSA-xxxx-yyyy-zzzz              # goes public
```

## Commands

### ls

Lists GitHub advisories: GHSA id, state, CVE id, severity and summary.
For GitLab, lists disclosure issues labeled `GSADV_ADVISORY_LABEL`, with `GL-` IDs,
CVE references and separate confidentiality indicators. GitLab filters are `all`,
`opened` and `closed`; see [GitLab disclosure issues](gitlab.md#disclosure-issues).
On GitHub, an optional state filters the results: `gsadv ls triage`, `gsadv ls draft`,
`gsadv ls published`, or `gsadv ls closed`. Omitting it, or using `all`, lists every state.

### log

Lists local commits matching `GSADV_GREP` and the advisory that references each of them.
By default, it matches `##crash`, `##security`, `##vulnerability` and `##sandbox` tags.
This is how you spot fixes that nobody reported yet:

```
gsadv log
8f3a2c1    2024-05-03  Fix heap overflow in PDB parser     GHSA-xxxx-yyyy-zzzz
1c2d3e4f5a 2024-04-28  Fix OOB read in the ELF loader     --------------------
```

### new

`gsadv new <commit|url> [context]` sends the source and your optional context to the AI
agent, opens the resulting advisory in `$EDITOR`, and creates a draft when you save.
Empty the editor buffer to abort. GitHub source paths are `owner/repo/issues/123`,
`owner/repo/pull/456`, or `owner/repo/commit/sha`. GitLab paths are
`group/subgroup/project/-/issues/123`, `/-/merge_requests/456`, or `/-/commit/sha`.
Use HTTPS URLs; custom hosts need an explicit provider. GitLab creation saves a
confidential issue labeled `GSADV_ADVISORY_LABEL`.
Query strings and fragments are stripped from source references.

Issues supply their body and discussion comments; PRs/MRs also supply merge metadata and a
patch. The agent investigates linked fixes and flags unknown versions. Draft creation
does not request a CVE or publish; run `cve <id>` after reviewing the draft.

### issues / tui label

```sh
gsadv -r owner/repo issues              # defaults to the cve label
gsadv -r owner/repo issues "needs-cve"
gsadv -r owner/repo tui "needs-cve"
```

Both commands accept an optional label, defaulting to `GSADV_LABEL` or `cve` when unset
or empty. The TUI always includes the third issues/PRs or issues/MRs tab. Items are fetched across
all pages and states, including closed issues and merged PRs/MRs. The list shows any advisory
referencing each item's URL. Press `n` in that tab to draft from the selected item.
The label is not removed after draft creation or CVE requests.

### show / edit

`show` prints the advisory in the text format. `edit` opens it in `$EDITOR` and sends a
GitHub `PATCH` or GitLab issue `PUT` on save, followed by reloading and checking the fields.

### review

`gsadv review <id> [context]` asks the agent to critique and rewrite the advisory, then
opens a diff for you to accept or reject line by line. See [the advisory](advisory-format.md)
for the diff rules.

### similar

`gsadv similar <id|commit|url> [context]` asks the agent to find other bugs with the same
root cause as the selected advisory or source. It includes an advisory referencing the
commit or issue/PR when available, and lists existing advisories for duplicate checking.
The agent investigates the current checkout and returns a Markdown findings report with
locations, triggers, evidence and confidence. Optional context narrows the search.

The report opens in the Markdown viewer (`r2`, otherwise `$PAGER`) and is saved as
`reply.txt` in the printed recovery directory. `gsadv resume <directory>` reopens it
without calling the AI. No advisory is created or updated. Press `b` in the TUI for
the same workflow. See [the search prompt](ai-agent.md#finding-similar-bugs).

### credits

`gsadv credits <id>` opens the credits TUI without running an AI agent. Add, edit or
delete username/role entries and browse the full role list with `?`. Press `s` to save
only the credits field. You can also reach this screen with `C` from the main TUI or
its actions menu. See [credits controls and roles](tui.md#credits-screen).

### resume

`gsadv resume <directory>` continues an interrupted or failed `new`, `edit` or `review`
using the recovery path printed before work began. It reopens the saved edits and uses
the saved repository and advisory ID, without calling the AI. Review errors offer
repairing the diff, using the full AI version, manual editing, or quitting while keeping
the files. See [recovery](advisory-format.md#recovery) for the files and Ctrl+C behavior.

For `similar`, it reopens the saved findings report, including partial output, without
running the AI or updating GitHub. Reports remain in the recovery directory after viewing.

### cve / approve

On GitLab, these commands show the disclosure URL and instructions for the separate
CVE request process. They do not submit a request or save an accepted-request receipt.
The following asynchronous API workflow applies to GitHub.

`gsadv cve <id>` requests a CVE for the existing advisory, including an already published
advisory. It does not publish, unpublish, or otherwise change the advisory's state.
`approve` remains an alias. If a CVE is already assigned, the command prints it without
submitting another request.

GitHub accepts the request asynchronously. Check `gsadv status <id>` or `gsadv ls` later.
A missing CVE ID alone does not tell you whether a request is pending: the REST response
does not expose that information. Successful requests from the CLI or TUI are saved
locally and shown as `requested*` in lists across restarts. `gsadv status <id>` shows
the recorded acceptance time until a CVE is assigned. This records an accepted request,
not its current position or status in GitHub's queue. See
[local record storage](configuration.md#local-cve-request-records).

The TUI suppresses repeat requests with a saved record. An explicit `gsadv cve <id>`
or `gsadv approve <id>` still allows a retry when no CVE has been assigned.

The equivalent direct command is:

```sh
gh api --method POST repos/OWNER/REPO/security-advisories/GHSA-xxxx-yyyy-zzzz/cve
```

CVE requests require a public repository and repository administrator or security-manager
access. See the [GitHub CVE request endpoint](https://docs.github.com/en/rest/security-advisories/repository-advisories#request-a-cve-for-a-repository-security-advisory).

### status

On GitLab, this shows the native issue state, confidentiality, referenced CVEs, timestamps
and URL. CVE references in text are not verification of assignment or publication.

On GitHub, `gsadv status <id>` shows the advisory state, assigned CVE, private-report acceptance,
timestamps (including withdrawal), private fork, and GitHub URL. Withdrawal is metadata,
not an additional state that this CLI can set.

### invalid / unmark

Record a local triage decision for an advisory/disclosure, commit, issue or PR/MR:

```sh
gsadv invalid GHSA-xxxx-yyyy-zzzz "No tagged release shipped vulnerable code"
gsadv invalid 8f3a2c1 "Introduced after v1.0 and fixed before v1.1"
gsadv invalid https://github.com/OWNER/REPO/issues/123 "Duplicate report"
gsadv invalid GHSA-xxxx-yyyy-zzzz       # read the saved reason
gsadv unmark GHSA-xxxx-yyyy-zzzz        # remove the tag
```

A nonempty reason sets or replaces the tag. Omitting it displays the saved reason.
Commits are stored by full SHA; short hashes and refs resolve in the current checkout,
which must belong to the selected repository. A full commit SHA or full-SHA URL also
works outside a checkout. URL query strings and fragments are ignored.

The CLI lists and TUI show `[invalid]`. In the TUI, `i` adds or edits the reason, `I`
clears it, and `/` searches `invalid` or words in the reason. Tagged items remain visible.
Marking a commit or issue does not implicitly mark its linked advisory, or vice versa.
On GitLab, `GL-123` and its issue URL identify the same tag.
Tags persist per provider, host and repository on this machine; they are not shared with
collaborators. See [storage](configuration.md#local-invalid-tags).

GitHub advisories have no native `invalid` state or custom labels. To keep the decision
upstream, use `gsadv edit <id>` to explain why no released version is affected, then
`gsadv close <id>` for an unpublished advisory/report. The local tag does not close
an advisory, change issue/PR labels, publish anything, or reject an assigned CVE.
GitHub's supported fields are listed in the
[advisory API](https://docs.github.com/en/rest/security-advisories/repository-advisories#update-a-repository-security-advisory).

### draft / publish / close / reopen

On GitLab, only `close` and `reopen` are supported; they preserve confidentiality.
On GitHub, `reopen` is an alias for changing the state to draft.

All lifecycle changes ask for confirmation. On GitHub, `draft` sets the advisory to draft, allowing a private
report in triage to be accepted or a closed advisory to be reopened. GitHub validates
state transitions. `publish` makes the advisory public; `close` closes an unpublished
advisory or rejects a report.

| State | Meaning | TUI actions |
| --- | --- | --- |
| `triage` | private report awaiting acceptance | accept as draft, close |
| `draft` | unpublished advisory being prepared | request CVE, publish, close |
| `published` | public advisory | request CVE if unassigned |
| `closed` | closed advisory/report | reopen as draft |

Editing, AI review, viewing and status remain available for each advisory. CVE request
actions disappear after assignment or while a saved record of an accepted request exists.
The API defines these [advisory states](https://docs.github.com/en/rest/security-advisories/repository-advisories#list-repository-security-advisories).
