# Usage

`ghav` is a CLI with an interactive TUI mode on top of it.

```
ghav [-r owner/repo] [command] [args]

  tui                     interactive list (default)
  ls [state]              list all/triage/draft/published/closed advisories
  log                     list ##crash/##security commits and their advisories
  new <commit> [context]  analyze a fix commit with AI and create a draft
  show <ghsa>             print advisory
  status <ghsa>           show lifecycle, CVE and private report details
  edit <ghsa>             edit advisory in $EDITOR
  review <ghsa> [context] let the AI review/rewrite it, then edit
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
3. `gh repo view --json nameWithOwner` in the current directory

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

`ghav new <commit> [context]` sends the commit patch and your optional context to the AI
agent, opens the resulting advisory in `$EDITOR`, and creates a draft when you save.

### show / edit

`show` prints the advisory in the text format. `edit` opens it in `$EDITOR` and sends a
`PATCH` on save.

### review

`ghav review <ghsa> [context]` asks the agent to critique and rewrite the advisory, then
opens a diff for you to accept or reject line by line. See [the advisory](advisory-format.md)
for the diff rules.

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
