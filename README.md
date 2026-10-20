# pantheon-skill-auditor

Skill quality auditor and offline skill validator for agent skills, as one binary:
`pantheon-skill-auditor`.

| Command | Purpose |
|---|---|
| `evaluate`, `batch` | Score skills against the 9-dimension quality framework (A to F) |
| `check-stored`, `duplication`, `prune-audits`, `plan-aggregation` | Stored audits and corpus-level analysis |
| `validate`, `check` | Offline structure, link, content and artifact validation (exit 0 clean, 1 error, 2 warning, 3 usage) |
| `probes` | Invocation probes: would a skill's description win the requests it should? |
| `analyze` | Content metrics, trigger-phrase drift and the shared skill-listing budget |
| `skill install` | Install the bundled `skill-quality-auditor` skill into detected agents |

The validator's flags work before or after the subcommand, as on the former standalone
`skill-validator-rs` binary, which this repository still builds as a thin wrapper.

## Install

Releases ship a shell installer and tarballs for macOS and Linux (arm64 and x86_64).
Until this repository has its own release, the latest is
[tekhne `tool/pantheon-skill-auditor-v0.3.0`](https://github.com/pantheon-org/tekhne/releases/tag/tool%2Fpantheon-skill-auditor-v0.3.0).

## Use in a workflow

```yaml
- uses: pantheon-org/pantheon-skill-auditor@<commit sha>
  with:
    version: "0.3.1"
    sha256: "<sha-256 of the linux x86_64 tarball>"
- run: pantheon-skill-auditor validate structure --allow-dirs=evals path/to/skill
```

## Development

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Some golden-corpus tests score live skills from a
[pantheon-org/tekhne](https://github.com/pantheon-org/tekhne) checkout. They skip themselves
unless `TEKHNE_ROOT` points at one; the frozen fixtures always run.

The shared helpers come from
[agentic-harness-dev-kit](https://github.com/pantheon-org/agentic-harness-dev-kit)
(`ahdk-core`, `ahdk-install`), pinned to a git tag until they are published to crates.io.

## History

Extracted from [pantheon-org/tekhne](https://github.com/pantheon-org/tekhne) with
`git filter-repo` (`crates/skill-validator-rs`, `crates/skill-auditor` and
`skills/agentic-harness/skill-quality-auditor`, now `skill-quality-auditor/`). Commit messages keep
their original `#NNN` references, which point at tekhne pull requests.
