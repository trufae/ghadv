# How it works

`ghav` is a thin wrapper around the GitHub REST API plus a couple of local edits, all done
through `gh api`.

`ghadv.v` parses arguments and dispatches commands. The repository-scoped `GitHub`
API in `github.v` owns all `gh` calls, endpoint paths, response queries and JSON
serialization. `workflow.v` handles AI and editor review, `advisory.v` handles the
editable format, and `sources.v` handles source URLs and local commits. `tui.v`
provides terminal views and calls the same API and workflows as the CLI.

| Operation | Endpoint |
| --- | --- |
| List / filter | `GET /repos/{owner}/{repo}/security-advisories` with optional `state` query |
| Read | `GET /repos/{owner}/{repo}/security-advisories/{ghsa_id}` |
| Create draft | `POST /repos/{owner}/{repo}/security-advisories` |
| Update draft | `PATCH /repos/{owner}/{repo}/security-advisories/{ghsa_id}` |
| Request CVE | `POST /repos/{owner}/{repo}/security-advisories/{ghsa_id}/cve` |
| Accept / reopen / publish / close | `PATCH .../{ghsa_id}` with `state=draft` / `published` / `closed` |
| Commit patch | `GET /repos/{owner}/{repo}/commits/{sha}` with the `vnd.github.patch` media type |
| Labeled issues/PRs | `GET /repos/{owner}/{repo}/issues?state=all&labels=...` (paginated) |
| Issue / PR details | `GET /repos/{owner}/{repo}/issues/{number}` or `.../pulls/{number}` |
| Discussion | `GET /repos/{owner}/{repo}/issues/{number}/comments` (paginated, also for PRs) |
| PR patch | `GET /repos/{owner}/{repo}/pulls/{number}` with the `vnd.github.patch` media type |

Advisories are read and written through the text format in
[advisory-format.md](advisory-format.md), which is converted to and from JSON before each
request.

CVE requests use a separate endpoint and do not change the advisory's state. `status`
reads the same advisory endpoint without converting lifecycle metadata to editable fields.

## Commit linking

Linking is local: the description of each advisory is scanned for 10–40 character hex ids,
and a commit is matched when its sha starts with one of them. That is what lets the commit
view show which fix already has an advisory.

Issue/PR linking scans advisory descriptions for full `https://github.com/owner/repo/issues/number`
or `/pull/number` references. Matching uses the entire URL, so issue 12 does not match 123.
No GitHub labels or issue/PR states are changed.
