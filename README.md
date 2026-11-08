# ghav

Manage GitHub repository security advisories (GHSA + CVE) from the terminal.
Single V file, no dependencies besides `gh` (authenticated with advisory write access).

```
make                # or: v -o ghav ghadv.v
make install        # copies ghav to ~/.local/bin
make uninstall
cd ~/radare2                       # repo is taken from the checkout, or -r owner/repo
ghav                               # TUI: tab j/k(J/K x10) enter e r n a p x g q
ghav new 8f3a2c1 found by fuzzing PDB files   # AI analysis -> $EDITOR -> draft
ghav ls | log
ghav show | edit | review | approve | publish | close <GHSA>
```

The TUI has two views, switched with `tab`: the advisories, and the fix commits in the
checkout tagged `##crash` or `##security` (`GHAV_GREP`), each showing the advisory that
references it. `n` on a commit drafts its advisory, `tab` jumps between a commit and its
advisory, and `e`/`r`/`a`/`p`/`x` act on the linked advisory from either view.

`review` opens a full-context unified diff (`.diff`) of the AI rewrite against the current
advisory, with the agent's notes above it. Delete a `+` line to reject an addition, delete a
`-` line to keep the original line, or edit `+` lines to reword them.

The AI agent is any command reading the prompt on stdin, set with `GHAV_AI`:
`claude -p` (default), `codex exec -` or `pmai "$(cat)"`; in the TUI, `A` cycles between these three. It runs in the cwd, so it can
build and test the checkout. Its reply (notes + advisory) is opened in `$EDITOR` before
anything is sent to GitHub (notes as `#` comments for `new`, a diff for `review`). The advisory format is plain text:

```
summary: Heap overflow in the PDB parser
severity: high          # dropped if cvss is set
cvss: CVSS:3.1/AV:L/...
cwe: CWE-787
credits: login:finder, login2:remediation_developer
package: radare2        # repeat package..functions for more entries
ecosystem: other
affected: >= 4.5.1, < 6.2.2
patched: 6.2.2
functions: r_bin_pdb_foo
---
markdown description
```

Empty the file (or leave an `edit` unchanged) to abort; `#` header lines are comments.
`approve` requests the CVE id (async, shows up later in `ls`); `publish` makes it public.

# Design notes

You can automate almost the entire CVE publication process from a GitHub PR or commit hash, including assigning a CVE ID, generating the advisory, and publishing it.

The trick is that GitHub Security Advisories and the CVE Program are two different systems, and GitHub already provides APIs for much of the bureaucracy.

For radare2, I'd build a small AI-powered CVE bot that takes:

```
cvebot radareorg/radare2 8f3a2c1
cvebot radareorg/radare2 --pr 27373
```

And performs this workflow:

GitHub PR / Commit

Repository, patch, commit history

AI security analysis

Root cause, affected versions, impact, CWE, reproducer

Draft GitHub Security Advisory

Description, references, severity, affected range

Human approval

Confirm security impact and disclosure readiness

Request CVE ID → Publish advisory

GitHub coordinates CVE assignment and publication

The important part: you don't necessarily need to become a CVE Numbering Authority (CNA) or interact directly with MITRE. GitHub can act as the CNA for eligible vulnerabilities disclosed through its repository security advisory system.

## 1. The API you're looking for already exists

GitHub added the CVE request endpoint in 2023.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://docs.github.com\&sz=32)

GitHub Docs+1



| Operation    | REST endpoint                                                                      |
| ------------ | ---------------------------------------------------------------------------------- |
| Create draft | `POST /repos/{owner}/{repo}/security-advisories`                                   |
| Update draft | `PATCH /repos/{owner}/{repo}/security-advisories/{ghsa_id}`                        |
| Request CVE  | `POST /repos/{owner}/{repo}/security-advisories/{ghsa_id}/cve`                     |
| Publish      | `PATCH /repos/{owner}/{repo}/security-advisories/{ghsa_id}` with `state=published` |

The CVE request returns HTTP `202 Accepted`, meaning the request was accepted, not necessarily that the identifier is immediately available.

### Example: request a CVE

```

gh api --method POST \
  repos/radareorg/radare2/security-advisories/GHSA-xxxx-yyyy-zzzz/cve

```

To publish after reviewing the advisory:

```

gh api --method PATCH \
  repos/radareorg/radare2/security-advisories/GHSA-xxxx-yyyy-zzzz \
  -f state=published

```

You need repository administration or security-manager access and a token with `Repository security advisories: write` permission.

## 2. What I'd automate with AI

The GitHub API is the easy part. The interesting work is reconstructing the vulnerability from the patch.

| Step        | AI's responsibility                                                 |
| ----------- | ------------------------------------------------------------------- |
| Detect      | Determine whether the patch fixes a real security vulnerability     |
| Analyze     | Find the root cause, attack surface, and exploitation preconditions |
| Verify      | Run a reproducer against vulnerable and patched revisions           |
| Classify    | Suggest CWE and CVSS with supporting evidence                       |
| Versions    | Find the first affected and first fixed releases                    |
| Deduplicate | Check existing GHSAs and CVEs for the same root cause               |
| Describe    | Generate a concise advisory, references, credits, and remediation   |
| Submit      | Create the GHSA draft, request CVE, and publish when approved       |

For radare2, the bot could build both revisions with ASan/UBSan and compare the behavior on the same input. This would help distinguish a genuine memory-safety fix from an ordinary bug fix.

I'd make the AI produce structured JSON and let deterministic code handle the GitHub API. That makes retries, validation, and duplicate prevention much simpler.

## 3. Two things I'd be careful about

One commit doesn't necessarily mean one CVE. A single patch might fix several independent vulnerabilities, or several commits might address one root cause. The bot should reason about that before submitting.

Affected versions are the biggest source of mistakes. Don't simply assume every version before the fixing commit is vulnerable. Inspect tags, backports, release branches, and whether the affected code existed in older releases.

Also, an already-public PR is not a reason to publish an unverified CVE immediately. I'd keep publication behind an explicit approval flag, while automating everything else.

## 4. My suggested implementation

I'd implement this as a small standalone CLI, initially in Python or TypeScript, using `gh` for authentication and GitHub REST calls:

```
cvebot analyze radareorg/radare2 --pr 27373
cvebot draft radareorg/radare2 --pr 27373
cvebot request GHSA-xxxx-yyyy-zzzz
cvebot publish GHSA-xxxx-yyyy-zzzz
```

Later, it could run as a GitHub Action triggered by a `security` label, a merged security-fix PR, or a manual workflow dispatch.

One useful distinction: GitHub's CNA workflow is suitable for eligible vulnerabilities in repositories you administer. For other vendors, or records assigned by another CNA, you'd need to follow that CNA's process rather than create a competing CVE.

The official API reference is here: [GitHub Repository Security Advisories REST API](https://docs.github.com/en/rest/security-advisories/repository-advisories?utm_source=chatgpt.com).

One design question: Do you want the bot to automatically request CVE IDs for every confirmed security fix, with approval only for publication, or require approval before requesting the ID too? I'd favor automatic draft creation, then one approval for requesting and publishing.
