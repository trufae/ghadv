# How it works

`ghav` is a thin wrapper around the GitHub REST API plus a couple of local edits, all done
through `gh api`.

| Operation | Endpoint |
| --- | --- |
| List | `GET /repos/{owner}/{repo}/security-advisories` |
| Read | `GET /repos/{owner}/{repo}/security-advisories/{ghsa_id}` |
| Create draft | `POST /repos/{owner}/{repo}/security-advisories` |
| Update draft | `PATCH /repos/{owner}/{repo}/security-advisories/{ghsa_id}` |
| Request CVE | `POST /repos/{owner}/{repo}/security-advisories/{ghsa_id}/cve` |
| Publish / close | `PATCH .../{ghsa_id}` with `state=published` / `closed` |
| Commit patch | `GET /repos/{owner}/{repo}/commits/{sha}` with the `vnd.github.patch` media type |

Advisories are read and written through the text format in
[advisory-format.md](advisory-format.md), which is converted to and from JSON before each
request.

## Commit linking

Linking is local: the description of each advisory is scanned for 10–40 character hex ids,
and a commit is matched when its sha starts with one of them. That is what lets the commit
view show which fix already has an advisory.
