# How it works

`gsadv` combines authenticated provider APIs with local AI/editor workflows.
GitHub requests use `gh api`; GitLab requests use `glab api`. API arguments are arrays,
and each request receives the resolved host explicitly.

`gsadv.v` parses arguments and dispatches commands. `repository.v` resolves provider,
host and project identity from options, source URLs and Git remotes. `provider.v`
exposes shared repository operations and supported states/actions. `github.v` and
`gitlab.v` own their respective endpoints, payloads and response handling.
`workflow.v` handles AI/editor review and recovery, `advisory.v` handles the editable
format, `sources.v` handles source URLs and local commits, and `triage.v` persists
local annotations. `tui.v` and `tui_data.v` use the same operations as the CLI.

The common list rows retain native state and identifiers. GitLab disclosure rows add a
separate visibility field; CVE values are extracted references. No issue is promoted to
a published advisory by normalizing its state.

## GitHub endpoints

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

## GitLab endpoints

Project paths, including subgroup separators, are URL-encoded as one API path segment.
List requests use `glab api --paginate --output ndjson`; JSON decoding stays inside V.
The provider does not depend on `jq` or GitLab Ultimate.

| Operation | Endpoint |
| --- | --- |
| List disclosure issues | `GET /projects/{path}/issues?scope=all&state=...&labels=...` |
| Read disclosure | `GET /projects/{path}/issues/{iid}` |
| Create disclosure | `POST /projects/{path}/issues` with title, description, label and `confidential=true` |
| Edit disclosure | `PUT /projects/{path}/issues/{iid}` with title and description only |
| Close/reopen | same `PUT` with `state_event=close` or `reopen` only |
| Labeled sources | separate paginated issue and merge-request lists with `state=all` |
| Source details | `GET /projects/{path}/issues/{iid}` or `.../merge_requests/{iid}` |
| Notes | `GET .../{iid}/notes?sort=asc` (paginated) |
| MR diffs | `GET .../merge_requests/{iid}/diffs` (paginated) |
| Commit details/diffs | `GET .../repository/commits/{sha}` and `.../{sha}/diff` |
| CVE request | read the disclosure and show instructions; no mutation |

`GL-123` refers to issue IID 123. Editable fields are serialized into marked Markdown
in its description; native title, state and confidentiality remain authoritative.
Content updates are reloaded and compared before success is reported. Provider, host,
project and disclosure label are saved in recovery sessions. See [GitLab support](gitlab.md)
for permissions and the distinction from Ultimate vulnerabilities and the advisory database.

## Commit linking

Linking is local: the description of each advisory is scanned for 10–40 character hex ids,
and a commit is matched when its sha starts with one of them. That is what lets the commit
view show which fix already has an advisory.

Issue/PR linking scans advisory descriptions for full `https://<host>/owner/repo/issues/number`
or `/pull/number` references on the selected GitHub host. Matching uses the entire URL,
so issue 12 does not match 123.
No GitHub labels or issue/PR states are changed.

GitLab linking also recognizes full issue, MR and commit URLs for the selected host and
project. A disclosure includes its own issue URL as a link, so selecting that issue can
jump to its disclosure entry. Local tags use the same identity for a `GL-` ID and its
canonical issue URL. Other linked sources retain independent tags.
