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
- Invalid input reopens the editor until it parses or you decline at the `[Y/n]` prompt.

For `new`, the agent's notes are shown above the advisory as `#` comments.

## Review diff

`review` opens a full-context unified diff of the AI rewrite against the current advisory,
with the reviewer notes above it. Editing the diff is the verdict:

- delete a `+` line to reject an addition
- delete a `-` line to keep the original
- edit a context line or a `+` line to reword it

The diff (produced with `diff -U 99999`, labeled `advisory` and `review`) is applied back
to the advisory and sent as a `PATCH`. An empty result aborts.
