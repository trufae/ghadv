# Advisory format

Advisories are edited as plain text: a short header, then the markdown description.

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

## Rules

- `#` lines are comments.
- `ecosystem`, `affected`, `patched` and `functions` attach to the preceding `package:`
  line. Repeat the group for more affected packages.
- `severity` is dropped when `cvss` is set — GitHub rejects both.
- `credits` entries default to type `finder` when written as a bare login.
- Empty the file, or leave it unchanged, to abort.
- Invalid plain-text input reopens the editor until it parses or you decline at the
  `[Y/n]` prompt. Invalid review diffs offer the recovery choices below.

For `new`, the agent's notes are shown above the advisory as `#` comments.

## Review diff

`review` opens a full-context unified diff of the AI rewrite against the current advisory,
with the reviewer notes above it. Editing the diff is the verdict:

- delete a `+` line to reject an addition
- delete a `-` line to keep the original
- edit a context line or a `+` line to reword it

The diff (produced with `diff -U 99999`, labeled `advisory` and `review`) is applied back
to the advisory and sent as a `PATCH`. An empty result aborts.

## Recovery

Before the AI or editor starts, `ghav` prints a private recovery directory and a command
to resume it. Each attempt has its own directory. It contains:

- `original.md`: the advisory before editing
- `prompt.txt` and `reply.txt`: the AI prompt and raw output, including partial output
- `notes.txt` and `proposed.md`: the AI notes and full proposed advisory
- `review.diff`: the diff, including your saved edits
- `result.md`: the latest reconstructed advisory
- `edit.md`: the plain-text buffer when editing directly or resolving a failed diff
- `session.json`: the repository, advisory ID and operation used by `resume`

Files appear as the workflow reaches each step. If applying the diff fails, its error
includes the failing line when available. Choose `d` to repair the diff, `n` to use the
full AI version, `m` to edit the result as plain text, or `q` (also Enter/EOF) to stop and
keep everything. When the diff cannot be reconstructed, manual editing starts with the
full AI version; the original advisory and edited diff remain available for comparison.
When reconstruction succeeds but parsing fails, manual editing starts with that result.
The full AI version still has to pass advisory validation before it can be saved.

If GitHub rejects the save, the error is shown and you can edit `result.md` or start from
`proposed.md` in a new plain-text buffer. Quitting preserves the files. Emptying the
editor or leaving a plain advisory unchanged still aborts without updating GitHub.
An editor that exits with a nonzero status also aborts without uploading its buffer.

Run `ghav resume <directory>` to continue without spending more AI tokens. It reopens the
saved buffer and uses the saved repository and advisory ID, regardless of the current
checkout. You can also inspect and repair the files first. Ctrl+C exits the workflow with
status 130 and keeps files already written, including partial agent output; it cannot
save an editor's unsaved buffer or output the agent has not emitted. If interrupted before
the advisory was extracted, repair `reply.txt` if needed, then resume.

Recovery files are removed after a successful GitHub save. Files you add to the recovery
directory are left alone. Aborted and failed attempts remain in the system temporary
directory; copy the directory elsewhere for longer-term storage. If a save was interrupted
or its response was lost, check GitHub before retrying, particularly when creating a new
advisory.
