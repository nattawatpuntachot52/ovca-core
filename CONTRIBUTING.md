# Contributing

Use a focused branch and keep changes within the public boundary described in
`docs/security-boundary.md`. Run Rust formatting, checks, tests, Clippy, and
the Python suite before opening a pull request. Add tests for changed behavior
and update documentation when authority or runtime surfaces change.

Do not submit secrets, private memory, historical datasets, local paths, logs,
PID files, generated reports, or News integrations. Contributions are accepted
under Apache-2.0.
