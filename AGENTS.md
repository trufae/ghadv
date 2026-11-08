# Project guidance

This is a small V CLI/TUI for managing GitHub repository security advisories.

- `ghadv.v` contains the application, including advisory parsing, editor review,
  AI integration, GitHub API calls, and the terminal interface.
- `README.md` documents usage and includes design notes. Check the source for
  current behavior; design notes may describe ideas that are not implemented.
- The executable is currently named `ghav`, and configuration uses `GHAV_*`
  environment variables. Keep those interfaces stable unless a change is requested.

## Development

- Keep changes focused and follow the existing V style. Prefer standard-library
  APIs and the existing helpers over new dependencies or abstractions.
- Use `gh` for GitHub authentication and API requests. Pass arguments as arrays;
  reserve shell execution for intentionally configurable commands such as
  `$EDITOR` and `GHAV_AI`.
- Preserve the editable advisory format, abort behavior, and review workflow.
- Update the README when changing commands, configuration, or user-visible behavior.

## Validation

Build with `v -o ghav ghadv.v`. For a local smoke check without replacing the
existing executable, build into a temporary directory and run help:

```sh
build_dir=$(mktemp -d)
v -o "$build_dir/ghav" ghadv.v
"$build_dir/ghav" --help
```

There is currently no automated test suite. For behavior changes, use focused
checks or tests covering the affected logic. Use a stub `gh` executable on `PATH`
when testing API interactions; routine validation should not mutate real advisories.
