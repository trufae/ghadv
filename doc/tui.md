# TUI

Running `ghav` with no command opens the TUI.

```sh
cd ~/radare2
ghav
```

Views, switched with `tab`:

| View | Shows |
| --- | --- |
| advisories | GHSA id, state, CVE id, severity, summary |
| commits | tagged fix commits (`GHAV_GREP`), date, subject, and the advisory referencing them |
| issues/PRs | items with `GHAV_LABEL` (or `ghav tui <label>`), number, type, state, linked advisory and title |

The issues/PRs tab appears only when a label is configured. It includes every state, so
closed issues and merged PRs remain available for reporting. `closed` in this list can
mean either a merged or a closed, unmerged PR; `enter` shows its merge metadata.

Keys:

| Key | Action |
| --- | --- |
| `j` / `k` | move one row |
| mouse wheel down / up | move one row, like `j` / `k` |
| `J` / `K` | move ten rows |
| `tab` | cycle views, selecting a linked entry in the next view when one exists |
| `enter` | show the commit (`git show`), advisory or issue/PR discussion (`r2` Markdown rendering if available, otherwise `$PAGER`) |
| `n` | draft from the selected commit or issue/PR; in the advisory view, prompt for a commit or URL and optional context |
| `e` | edit the linked advisory |
| `r` | AI-review the linked advisory |
| `b` | find similar bugs using the selected advisory or source as a template |
| `C` | manage credited people and roles for the linked advisory |
| `m` | open the selected advisory's actions menu |
| `c` / `a` | request a CVE, including for a published advisory |
| `d` | accept a triage report or reopen a closed advisory as draft |
| `p` | publish |
| `x` | close (asks `[y/N]`) |
| `s` | show lifecycle, CVE, private-report status, timestamps and URL |
| `f` | cycle all / triage / draft / published / closed |
| `A` | cycle the AI agent preset |
| `g` | reload all lists |
| `?` | show all keys and the active AI agent |
| `q` / `Ctrl+C` | quit from the main list |

In the commit and issues/PRs views, advisory actions act on the advisory that references
the selected item. If there is none, press `n` to prepare a draft, review it in `$EDITOR`,
then `c` to request a CVE. Issue/PR links require their full URL in the advisory description.
Creating a draft does not request a CVE, publish, or remove the label.

`b` also works on commits and issues/PRs without a linked advisory. It prompts for optional
search instructions, such as "Look for the same missing bounds check in related parsers
and callers." Enter starts; Escape or Ctrl+C cancels. The selected source and any linked
advisory are sent to the configured AI, which searches the current checkout for related
mistakes. The findings report opens in the Markdown viewer; it does not update an advisory.
The source, prompt and reply remain in the printed recovery directory. Use
`ghav resume <directory>` to reopen the report. See [the search prompt](ai-agent.md#finding-similar-bugs).

The `r` prompt accepts optional review instructions, for example: "Check the affected
versions and whether the fix addresses the root cause." Press Enter to start, or Ctrl+C
or Escape to cancel without running the AI. The `n` input prompt accepts the same cancel
keys. Ctrl+C while the AI is running or at a recovery prompt cancels that operation and
returns to the list, keeping the recovery files printed before it started. An interrupted
editor also returns to the list with terminal settings restored; unsaved editor buffers
cannot be recovered by `ghav`.

After a review or edit, enter `v` to view the current advisory, `r` to review it again
with new context, `b` to find similar bugs, or `e` to edit it. The same prompt appears after
closing the advisory viewer. Enter alone, Escape or Ctrl+C returns to the list. Views and reviews fetch the
advisory from GitHub each time. A save is reported only after reloading and checking the
editable fields; verification failures retain the recovery files.

The bottom two rows separate colored keys from descriptions. The action row and `m` menu
offer actions appropriate to the selected advisory's state and CVE assignment. The status
line above them shows the selection or the result of the last action. All lifecycle and
CVE actions require confirmation; errors leave the advisory unchanged locally.

Published advisories without a CVE offer `c request CVE`. On success, the list shows
`requested*`, meaning GitHub accepted a request during this session. This is a local
acknowledgement, not a new advisory state or an API-reported pending status. Press `g`
to refresh the assigned CVE; `s` displays the latest server details. Repeat requests are
suppressed for the rest of the session, and assigned IDs replace the marker on refresh.

The state filter applies only to the advisory list; source links still use all advisories.
Jumping to a linked advisory outside the current filter switches back to all.

## Credits screen

Press `C` in the list or actions menu, or run `ghav credits <ghsa>` directly. In the
commit and issue/PR views, this opens credits for the linked advisory. The screen lists
each GitHub username and role, with an explanation of the selected role below the list.

| Key | Action |
| --- | --- |
| `a` | add a username and choose a role |
| `e` / `enter` | edit the selected username and role |
| `d` / `x` | remove the selected entry locally |
| `j` / `k`, arrows, mouse wheel | move through entries or the role picker |
| `J` / `K` | move ten entries |
| `?` | browse every supported role without changing entries |
| `s` | save the current credits to GitHub |
| `u` | undo all changes since opening the screen or the last successful save |
| `q` / `Esc` / `Ctrl+C` | return; if changed, choose save, discard or cancel |

Usernames accept an optional leading `@`. In the username form, Backspace deletes,
Ctrl+U clears the current name, and Enter continues to the role picker. Escape or Ctrl+C
cancels either form without changing the list. Pick a role with arrows or `j`/`k` and
Enter, or choose its numbered shortcut (`1`–`9`, `0` for the tenth role).

The [GitHub credit roles](https://docs.github.com/en/rest/security-advisories/repository-advisories#update-a-repository-security-advisory)
are:

| Role | Contribution |
| --- | --- |
| `finder` | discovered the vulnerability |
| `reporter` | reported the vulnerability |
| `analyst` | analyzed or documented the vulnerability |
| `coordinator` | coordinated disclosure and response |
| `remediation_developer` | developed the fix |
| `remediation_reviewer` | reviewed the fix |
| `remediation_verifier` | verified the fix |
| `tool` | tool used in discovery or investigation |
| `sponsor` | supported or funded the work |
| `other` | another contribution |

Add separate entries if one person has several roles, such as finder and reporter.
Duplicate username/role pairs are rejected, ignoring username case. GitHub validates
that the usernames exist when saving. A failed save displays the error and retains your
staged edits for correction or retry. Deleting every entry and saving clears all credits.
Only the credits field is updated; the advisory text, severity and other fields are
unaffected. This screen does not run the AI, and the plain-text `credits:` format remains
available in the regular editor.

## Terminal behavior

After leaving the `r2` or pager view, use the advisory action prompt to view, review or
edit again, or press Enter to return to the list.

Mouse reporting is enabled while the TUI is active, so the wheel moves the selection
instead of the terminal scrollback. It is disabled when opening a viewer, editor or
prompt in cooked mode, and when quitting.

The header shows the repository, active view and advisory filter. Pressing `A`
cycles through `claude -p`, `codex exec -` and `pmai "$(cat)"`; a custom `GHAV_AI` is
replaced by the first preset. The selected agent appears in the status line and `?` help.
