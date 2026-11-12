# Advisory format

GitHub advisories and GitLab disclosure issues use the same editable text: a short
header, then the Markdown description. See [GitLab storage](gitlab.md#disclosure-issues).

```
summary: Heap overflow in the PDB parser
severity: high
cvss: CVSS:3.1/AV:L/...
cwe: CWE-787
credits: login:finder, login2:remediation_developer
package: radare2
ecosystem: other
affected: >= 4.5.1, < 6.2.2
patched: 6.2.2
---
markdown description
```

## Rules

- `#` lines before `---` are editor comments and are not saved to the provider. After `---`,
  Markdown headings and all other description text are part of the advisory.
- `ecosystem`, `affected` and `patched` attach to the preceding `package:`
  line. Repeat the group for more affected packages.
- `severity` is dropped when `cvss` is set — GitHub rejects both.
- Nonempty `functions:` fields are rejected; name affected functions in the description.
- `credits` entries default to type `finder` when written as a bare login.
- Empty the file, or leave it unchanged, to abort.
- Invalid plain-text input reopens the editor until it parses or you decline at the
  `[Y/n]` prompt. Invalid review diffs offer the recovery choices below.

For `new`, the agent's brief editorial notes are shown above the advisory as `#` comments.
Useful findings, evidence, references to related findings, caveats and attribution must be
included in the advisory fields or description below `---`, not only in these comments.
Both drafting and review ask the agent to fill missing credits from verified source evidence
and retain other names, handles and scan IDs in Acknowledgements.

On GitHub, credits can also be managed with `C` in the TUI or `gsadv credits <ghsa>`, using a separate
screen with add/edit/delete controls and descriptions of all credit roles. See the
[credits screen](tui.md#credits-screen). It updates only credits and leaves this editable
format unchanged.

## Review diff

`review` opens a full-context unified diff of the AI rewrite against the current advisory,
with the reviewer notes above it. Editing the diff is the verdict:

- delete a `+` line to reject an addition
- delete a `-` line to keep the original
- edit a context line or a `+` line to reword it

The diff (produced with `diff -U 99999`, labeled `advisory` and `review`) is applied back
to the advisory and sent as a GitHub `PATCH` or GitLab issue `PUT`. Leaving the diff unchanged accepts all proposed
changes; emptying the file or producing the original advisory aborts. If the AI proposes
no changes, its notes are shown without opening the editor. Changes only to comments or
formatting also abort without a save. After updating, `gsadv` reloads the advisory and
compares its editable fields before printing `Saved changes to <id> on <provider>.`.
If the reloaded fields differ or cannot be fetched, the error is shown and recovery
files are kept. In the TUI, enter `v` at the following prompt to view the current version,
`r` to review it again, or `e` to edit it; Enter alone returns to the list.

## Recovery

Before the AI or editor starts, `gsadv` prints a private recovery directory and a command
to resume it. If the AI fails or replies without an advisory, the error includes a preview
of its captured reply and states that no changes were saved. Each attempt has its own
directory. It contains:

- `original.md`: the advisory before editing
- `prompt.txt` and `reply.txt`: the AI prompt and raw output, including partial output
- `notes.txt` and `proposed.md`: the AI notes and full proposed advisory
- `review.diff`: the diff, including your saved edits
- `result.md`: the latest reconstructed advisory
- `edit.md`: the plain-text buffer when editing directly or resolving a failed diff
- `session.json`: the provider, host, repository, advisory ID, operation and GitLab disclosure label used by `resume`

Files appear as the workflow reaches each step. If applying the diff fails, its error
includes the failing line when available. Choose `d` to repair the diff, `n` to use the
full AI version, `m` to edit the result as plain text, or `q` (also Enter/EOF) to stop and
keep everything. When the diff cannot be reconstructed, manual editing starts with the
full AI version; the original advisory and edited diff remain available for comparison.
When reconstruction succeeds but parsing fails, manual editing starts with that result.
The full AI version still has to pass advisory validation before it can be saved.

If the provider rejects the save, the error is shown and you can edit `result.md` or start from
`proposed.md` in a new plain-text buffer. Quitting preserves the files. Emptying the
editor or leaving a plain advisory unchanged still aborts without updating the provider.
An editor that exits with a nonzero status also aborts without uploading its buffer.

Run `gsadv resume <directory>` to continue without spending more AI tokens. It reopens the
saved buffer and uses the saved provider, host, repository and advisory ID, regardless of the current
checkout. You can also inspect and repair the files first. Ctrl+C during the AI or a
recovery prompt cancels the operation and returns to the list in the TUI. Standalone CLI
workflows exit with status 130. Both keep files already written, including partial agent output; they cannot
save an editor's unsaved buffer or output the agent has not emitted. If interrupted before
the advisory was extracted, repair `reply.txt` if needed, then resume.

Recovery files are removed after a successful save. Files you add to the recovery
directory are left alone. Aborted and failed attempts remain in the system temporary
directory; copy the directory elsewhere for longer-term storage. If a save was interrupted
or its response was lost, check the provider before retrying, particularly when creating a new
advisory.
