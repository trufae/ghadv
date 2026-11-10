# Design notes

Short version of the reasoning behind the tool.

- **GitHub is the CNA for the GitHub workflow.** For eligible repos you do not talk to MITRE; the advisory API handles
  CVE assignment. `POST .../cve` returns `202 Accepted`, so the id is not instant.
- **The API is the easy part.** The hard work is reconstructing the vulnerability from the
  patch: is it a real security fix, root cause, attack surface, CWE, CVSS, first affected and
  first fixed release, duplicates.
- **Affected versions are the main source of mistakes.** Do not assume every release before the
  fix is vulnerable. Check tags, backports and when the vulnerable code was introduced — the
  agent is told this explicitly.
- **One commit is not one CVE.** A patch may fix several independent bugs, or several commits
  one root cause. The agent reports the most important one and explains the other verified findings in the description.
- **Keep publication behind an approval.** `publish`, `close` and `draft` ask for
  confirmation, as do GitHub lifecycle/CVE actions in the TUI. The explicit CLI `cve`
  command (also named `approve` for compatibility) submits a GitHub request directly.
  GitLab `cve` displays instructions and never submits a request.
- **Text in, JSON out.** The advisory is a plain-text format that is easy to edit in `$EDITOR`
  and diff for review; JSON conversion stays deterministic in the tool.
- **Share workflows, preserve provider differences.** GitLab disclosures use confidential
  labeled issues. Native issue state and confidentiality stay separate; the shared TUI
  exposes supported actions rather than assigning GitHub publication states to issues.
  GitLab's Ultimate vulnerability report is a different source of security findings and
  is outside the current integration. See [GitLab support](gitlab.md).

## Limitations

- Focused source-URL and advisory-link tests run with `v test ghadv_test.v`. Build with
  `v -o ghadv .`. Run `v test .` for all focused tests and
  `python3 test/gitlab_smoke.py /path/to/ghadv` for offline GitHub/GitLab integration
  checks with stub CLIs, including POSIX TUI checks.
- The commit view only sees commits matching `GHADV_GREP` in the local checkout.
- Advisory↔commit linking relies on 10–40 char hex ids appearing in the description.
- Source linking requires full URLs in the disclosure description. GitHub PR evidence
  includes issue comments, not inline review threads; GitLab uses issue/MR notes.
- Custom hosts require an explicit provider, and SSH aliases are not expanded.
- GitLab CVEs are text references; the CLI does not verify assignment, submit CNA
  requests or publish CVE records. GitLab visibility changes are performed on the website.
