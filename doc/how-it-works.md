# How it works

`ghav` is a thin wrapper around the GitHub REST API plus a couple of local edits, all done
through `gh api`.

| Operation | Endpoint |
| --- | --- |
| List / filter | `GET /repos/{owner}/{repo}/security-advisories` with optional `state` query |
| Read | `GET /repos/{owner}/{repo}/security-advisories/{ghsa_id}` |
| Create draft | `POST /repos/{owner}/{repo}/security-advisories` |
| Update draft | `PATCH /repos/{owner}/{repo}/security-advisories/{ghsa_id}` |
| Request CVE | `POST /repos/{owner}/{repo}/security-advisories/{ghsa_id}/cve` |
| Accept / reopen / publish / close | `PATCH .../{ghsa_id}` with `state=draft` / `published` / `closed` |
| Commit patch | `GET /repos/{owner}/{repo}/commits/{sha}` with the `vnd.github.patch` media type |

Advisories are read and written through the text format in
[advisory-format.md](advisory-format.md), which is converted to and from JSON before each
request.

CVE requests use a separate endpoint and do not change the advisory's state. `status`
reads the same advisory endpoint without converting lifecycle metadata to editable fields.

## Commit linking

Linking is local: the description of each advisory is scanned for 10–40 character hex ids,
and a commit is matched when its sha starts with one of them. That is what lets the commit
view show which fix already has an advisory.
