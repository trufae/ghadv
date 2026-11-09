# Usage

`ghav` is a CLI with an interactive TUI mode on top of it.

```
ghav [-r owner/repo] [command] [args]

  tui [label]             advisory, commit and labeled issues/PRs tabs (default)
  ls [state]              list all/triage/draft/published/closed advisories
  log                     list ##crash/##security commits and their advisories
  issues [label]          list labeled issues/PRs (default: GHAV_LABEL or cve)
  new <commit|url> [context] analyze a commit, issue or PR with AI and create a draft
  show <ghsa>             print advisory
  status <ghsa>           show lifecycle, CVE and private report details
  credits <ghsa>          manage credited people and roles in the TUI
  edit <ghsa>             edit advisory in $EDITOR
  review <ghsa> [context] let the AI review/rewrite it, then edit
  similar <ghsa|commit|url> [context] find similar bugs using the selection as a template
  resume <directory>     continue saved work without running the AI again
  cve <ghsa>              request a CVE id (asynchronous)
  approve <ghsa>          alias for cve
  draft <ghsa>            accept a report or reopen as a draft
  publish <ghsa>          publish the advisory
  close <ghsa>            close (reject) the advisory
```

`-h`, `--help` or `help` prints the same text.

## Repository

The repository is resolved in this order:

1. `-r owner/repo`
2. `$GHAV_REPO`
3. The GitHub URL for `new <url>` or `similar <url>` (must match an explicit repository above)
4. `gh repo view --json nameWithOwner` in the current directory

If none works, `ghav` exits with `cannot find repository, use -r owner/repo or GHAV_REPO`.

## Typical flow

```sh
cd ~/radare2
ghav new 8f3a2c1 found by fuzzing PDB files   # AI analysis -> $EDITOR -> draft
ghav review GHSA-xxxx-yyyy-zzzz               # AI review as a diff -> $EDITOR
ghav cve GHSA-xxxx-yyyy-zzzz                  # request the CVE id (async)
ghav status GHSA-xxxx-yyyy-zzzz               # check assignment and lifecycle
ghav publish GHSA-xxxx-yyyy-zzzz              # goes public
```

## Commands

### ls

Lists the advisories of the repository: GHSA id, state, CVE id, severity and summary.
An optional state filters the results: `ghav ls triage`, `ghav ls draft`,
`ghav ls published`, or `ghav ls closed`. Omitting it, or using `all`, lists every state.

### log

Lists local commits matching `GHAV_GREP` and the advisory that references each of them.
This is how you spot fixes that nobody reported yet:

```
ghav log
8f3a2c1    2024-05-03  Fix heap overflow in PDB parser     GHSA-xxxx-yyyy-zzzz
1c2d3e4f5a 2024-04-28  Fix OOB read in the ELF loader     --------------------
```

### new

`ghav new <commit|url> [context]` sends the source and your optional context to the AI
agent, opens the resulting advisory in `$EDITOR`, and creates a draft when you save.
Empty the editor buffer to abort. Supported URLs are HTTPS `github.com` URLs with paths
`owner/repo/issues/123`, `owner/repo/pull/456`, or `owner/repo/commit/sha`.
Query strings and fragments are stripped from source references.

Issues supply their body and discussion comments; PRs also supply merge metadata and a
patch. The agent investigates linked fixes and flags unknown versions. Draft creation
does not request a CVE or publish; run `cve <ghsa>` after reviewing the draft.

### issues / tui label

```sh
ghav -r owner/repo issues              # defaults to the cve label
ghav -r owner/repo issues "needs-cve"
ghav -r owner/repo tui "needs-cve"
```

Both commands accept an optional label, defaulting to `GHAV_LABEL` or `cve` when unset
or empty. The TUI always includes the third issues/PRs tab. Items are fetched across
all pages and states, including closed issues and merged PRs. The list shows any advisory
referencing each item's URL. Press `n` in that tab to draft from the selected item.
The label is not removed after draft creation or CVE requests.

### show / edit

`show` prints the advisory in the text format. `edit` opens it in `$EDITOR` and sends a
`PATCH` on save.

### review

`ghav review <ghsa> [context]` asks the agent to critique and rewrite the advisory, then
opens a diff for you to accept or reject line by line. See [the advisory](advisory-format.md)
for the diff rules.

### similar

`ghav similar <ghsa|commit|url> [context]` asks the agent to find other bugs with the same
root cause as the selected advisory or source. It includes an advisory referencing the
commit or issue/PR when available, and lists existing advisories for duplicate checking.
The agent investigates the current checkout and returns a Markdown findings report with
locations, triggers, evidence and confidence. Optional context narrows the search.

The report opens in the Markdown viewer (`r2`, otherwise `$PAGER`) and is saved as
`reply.txt` in the printed recovery directory. `ghav resume <directory>` reopens it
without calling the AI. No advisory is created or updated. Press `b` in the TUI for
the same workflow. See [the search prompt](ai-agent.md#finding-similar-bugs).

### credits

`ghav credits <ghsa>` opens the credits TUI without running an AI agent. Add, edit or
delete username/role entries and browse the full role list with `?`. Press `s` to save
only the credits field. You can also reach this screen with `C` from the main TUI or
its actions menu. See [credits controls and roles](tui.md#credits-screen).

### resume

`ghav resume <directory>` continues an interrupted or failed `new`, `edit` or `review`
using the recovery path printed before work began. It reopens the saved edits and uses
the saved repository and advisory ID, without calling the AI. Review errors offer
repairing the diff, using the full AI version, manual editing, or quitting while keeping
the files. See [recovery](advisory-format.md#recovery) for the files and Ctrl+C behavior.

For `similar`, it reopens the saved findings report, including partial output, without
running the AI or updating GitHub. Reports remain in the recovery directory after viewing.

### cve / approve

`ghav cve <ghsa>` requests a CVE for the existing advisory, including an already published
advisory. It does not publish, unpublish, or otherwise change the advisory's state.
`approve` remains an alias. If a CVE is already assigned, the command prints it without
submitting another request.

GitHub accepts the request asynchronously. Check `ghav status <ghsa>` or `ghav ls` later.
A missing CVE ID alone does not tell you whether a request is pending: the REST response
does not expose that information. The TUI remembers successful requests for its current
session and marks them `requested*`.

The equivalent direct command is:

```sh
gh api --method POST repos/OWNER/REPO/security-advisories/GHSA-xxxx-yyyy-zzzz/cve
```

CVE requests require a public repository and repository administrator or security-manager
access. See the [GitHub CVE request endpoint](https://docs.github.com/en/rest/security-advisories/repository-advisories#request-a-cve-for-a-repository-security-advisory).

### status

`ghav status <ghsa>` shows the advisory state, assigned CVE, private-report acceptance,
timestamps (including withdrawal), private fork, and GitHub URL. Withdrawal is metadata,
not an additional state that this CLI can set.

### draft / publish / close

All three ask for confirmation. `draft` sets the advisory to draft, allowing a private
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
actions disappear after assignment or after a successful request in the current session.
The API defines these [advisory states](https://docs.github.com/en/rest/security-advisories/repository-advisories#list-repository-security-advisories).
