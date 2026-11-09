# Project guidance

This is a small V CLI/TUI for managing GitHub repository security advisories.

- `ghadv.v` contains argument parsing, help and command dispatch.
- `github.v` owns the repository-scoped `GitHub` API and all `gh` requests.
- `tui.v` contains terminal views, formatting, navigation and action prompts.
- `workflow.v` handles AI, editor and advisory review workflows; `advisory.v`
  defines the advisory types, editable format parser and source linking.
- `sources.v` parses commit/issue/PR inputs and discovers local fix commits.
- `README.md` documents usage and includes design notes. Check the source for
  current behavior; design notes may describe ideas that are not implemented.
- The documented CLI name is `ghav`; the Makefile defaults to `ghadv` and accepts
  `BIN=ghav`. Configuration uses `GHAV_*` environment variables. Keep those
  interfaces stable unless a change is requested.

## Development

- Keep changes focused and follow the existing V style. Prefer standard-library
  APIs and the existing helpers over new dependencies or abstractions.
- Use `gh` for GitHub authentication and API requests. Pass arguments as arrays;
  reserve shell execution for intentionally configurable commands such as
  `$EDITOR` and `GHAV_AI`.
- Keep GitHub endpoints and payload handling in `github.v`; CLI, TUI and workflow
  code should call its repository-scoped methods.
- Preserve the editable advisory format, abort behavior, and review workflow.
- Update the README when changing commands, configuration, or user-visible behavior.

## Validation

Build the shared module with `v -o ghav .`. For a local smoke check without replacing the
existing executable, build into a temporary directory and run help:

```sh
build_dir=$(mktemp -d)
v -o "$build_dir/ghav" .
"$build_dir/ghav" --help
```

Run the focused source parsing and linking tests with `v test ghadv_test.v`.
For behavior changes, use focused checks or tests covering the affected logic.
Use a stub `gh` executable on `PATH`
when testing API interactions; routine validation should not mutate real advisories.
