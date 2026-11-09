# Design notes

Short version of the reasoning behind the tool.

- **GitHub is the CNA.** For eligible repos you do not talk to MITRE; the advisory API handles
  CVE assignment. `POST .../cve` returns `202 Accepted`, so the id is not instant.
- **The API is the easy part.** The hard work is reconstructing the vulnerability from the
  patch: is it a real security fix, root cause, attack surface, CWE, CVSS, first affected and
  first fixed release, duplicates.
- **Affected versions are the main source of mistakes.** Do not assume every release before the
  fix is vulnerable. Check tags, backports and when the vulnerable code was introduced — the
  agent is told this explicitly.
- **One commit is not one CVE.** A patch may fix several independent bugs, or several commits
  one root cause. The agent reports the most important one and lists the rest in its notes.
- **Keep publication behind an approval.** `publish`, `close` and `draft` ask for
  confirmation, as do all lifecycle/CVE actions in the TUI. The explicit CLI `cve`
  command (also named `approve` for compatibility) submits a request directly.
- **Text in, JSON out.** The advisory is a plain-text format that is easy to edit in `$EDITOR`
  and diff for review; JSON conversion stays deterministic in the tool.

## Limitations

- Focused source-URL and advisory-link tests run with `v test ghadv_test.v`. Build with
  `v -o ghav .`; use a stub `gh` on `PATH` when exercising API interactions.
- The commit view only sees commits matching `GHAV_GREP` in the local checkout.
- Advisory↔commit linking relies on 10–40 char hex ids appearing in the description.
- Issue/PR linking requires a full GitHub URL in the advisory description. Source URLs
  currently support `github.com`; PR discussion includes issue comments, not inline review threads.
