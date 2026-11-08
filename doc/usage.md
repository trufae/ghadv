# Usage

`ghav` is a CLI with an interactive TUI mode on top of it.

```
ghav [-r owner/repo] [command] [args]

  tui                     interactive list (default)
  ls                      list advisories
  log                     list ##crash/##security commits and their advisories
  new <commit> [context]  analyze a fix commit with AI and create a draft
  show <ghsa>             print advisory
  edit <ghsa>             edit advisory in $EDITOR
  review <ghsa> [context] let the AI review/rewrite it, then edit
  approve <ghsa>          request a CVE id
  publish <ghsa>          publish the advisory
  close <ghsa>            close (reject) the advisory
```

`-h`, `--help` or `help` prints the same text.

## Repository

The repository is resolved in this order:

1. `-r owner/repo`
2. `$GHAV_REPO`
3. `gh repo view --json nameWithOwner` in the current directory

If none works, `ghav` exits with `cannot find repository, use -r owner/repo or GHAV_REPO`.

## Typical flow

```sh
cd ~/radare2
ghav new 8f3a2c1 found by fuzzing PDB files   # AI analysis -> $EDITOR -> draft
ghav review GHSA-xxxx-yyyy-zzzz               # AI review as a diff -> $EDITOR
ghav approve GHSA-xxxx-yyyy-zzzz              # request the CVE id (async)
ghav publish GHSA-xxxx-yyyy-zzzz              # goes public
```

## Commands

### ls

Lists the advisories of the repository: GHSA id, state, CVE id, severity and summary.

### log

Lists local commits matching `GHAV_GREP` and the advisory that references each of them.
This is how you spot fixes that nobody reported yet:

```
ghav log
8f3a2c1    2024-05-03  Fix heap overflow in PDB parser     GHSA-xxxx-yyyy-zzzz
1c2d3e4f5a 2024-04-28  Fix OOB read in the ELF loader     --------------------
```

### new

`ghav new <commit> [context]` sends the commit patch and your optional context to the AI
agent, opens the resulting advisory in `$EDITOR`, and creates a draft when you save.

### show / edit

`show` prints the advisory in the text format. `edit` opens it in `$EDITOR` and sends a
`PATCH` on save.

### review

`ghav review <ghsa> [context]` asks the agent to critique and rewrite the advisory, then
opens a diff for you to accept or reject line by line. See [the advisory](advisory-format.md)
for the diff rules.

### approve / publish / close

`approve` requests the CVE id asynchronously — GitHub returns `202 Accepted` and the CVE
shows up later in `ls` / `show`. `publish` and `close` ask for confirmation.
