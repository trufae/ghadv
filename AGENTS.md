# Project guidance

This is a small V CLI/TUI for managing GitHub repository security advisories and
GitLab disclosures stored as confidential labeled issues.

- `gsadv.v` contains argument parsing, help and command dispatch.
- `repository.v` owns provider/host/project identity and remote detection;
  `provider.v` dispatches repository operations and exposes supported actions.
- `github.v` owns GitHub endpoints and all `gh` requests; `gitlab.v` owns
  GitLab endpoints, disclosure serialization and all `glab` requests.
- `tui.v` contains terminal views, formatting, navigation and action prompts.
- `workflow.v` handles AI, editor and advisory review workflows; `advisory.v`
  defines the advisory types, editable format parser and source linking.
- `sources.v` parses commit/issue/PR inputs and discovers local fix commits.
- `README.md` documents usage and includes design notes. Check the source for
  current behavior; design notes may describe ideas that are not implemented.
- The CLI name and default Makefile binary are `gsadv`; `BIN` is overridable.
  Configuration uses `GSADV_*` environment variables with legacy `GHADV_*` aliases. Keep those
  interfaces stable unless a change is requested.

## Development

- Keep changes focused and follow the existing V style. Prefer standard-library
  APIs and the existing helpers over new dependencies or abstractions.
- Use `gh` for GitHub and `glab` for GitLab authentication and API requests. Pass arguments as arrays;
  reserve shell execution for intentionally configurable commands such as
  `$EDITOR` and `GSADV_AI`.
- Keep endpoints and payload handling in the provider's file; CLI, TUI and workflow
  code should call the repository-scoped methods. Keep GitLab issue state and visibility
  separate; editing, closing or reopening must not change confidentiality.
- Preserve the editable advisory format, abort behavior, and review workflow.
- Update the README when changing commands, configuration, or user-visible behavior.

## Validation

Build the shared module with `v -o gsadv .`. For a local smoke check without replacing the
existing executable, build into a temporary directory and run help:

```sh
build_dir=$(mktemp -d)
v -o "$build_dir/gsadv" .
"$build_dir/gsadv" --help
```

Run the focused source parsing and linking tests with `v test gsadv_test.v`.
For behavior changes, use focused checks or tests covering the affected logic.
Use a stub `gh` executable on `PATH`
when testing API interactions; routine validation should not mutate real advisories.
`v test .` also covers provider identity, GitLab formatting, recovery and TUI behavior.
Run `python3 test/gitlab_smoke.py /path/to/temporary/gsadv` for offline end-to-end checks
with stub `gh` and `glab` executables, including a POSIX pseudo-terminal smoke test.
