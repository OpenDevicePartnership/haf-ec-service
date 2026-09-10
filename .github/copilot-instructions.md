# Copilot instructions

See [`AGENTS.md`](../AGENTS.md) in the repository root for the full agent
guidance. That file is the single source of truth for build commands,
workspace layout, conventions, and PR workflow used by GitHub Copilot and
other AI coding assistants.

Short version:

- Cargo workspace, `resolver = "2"`, edition `2021`, MSRV **1.85**.
- Targets host plus `aarch64-unknown-none[-softfloat]` (`no_std` for the
  secure-partition crates under `platform/`).
- Before finishing any change, run `.husky/pre-commit` and make sure it
  passes (fmt, clippy, `cargo hack` feature powerset on host and aarch64,
  host tests, and per-platform `cargo build`).
- Clippy lint floor is `suspicious / correctness / perf / style = deny`
  (set in the workspace `Cargo.toml`); do not relax it.
- `rustfmt.toml` sets `max_width = 120`. Use LF line endings.
- Prefer `[workspace.dependencies]` entries with
  `dep = { workspace = true }` in member crates.
- `CODEOWNERS` requires
  `@OpenDevicePartnership/odp-platform-maintainers`; changes under
  `**/supply-chain` additionally require
  `@OpenDevicePartnership/crate-auditors`.
