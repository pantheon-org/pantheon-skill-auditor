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

`validate structure`, `check` and `analyze content` also take a directory of skills. When the path has no
`SKILL.md`, every skill up to six levels below it is checked and the report ends with totals; `--max-depth=N`
changes the depth, and `--max-depth=0` checks the path alone.
Add `-o compact` for one line per skill with only its warnings and errors beneath it.

`validate security <dir>` runs offline security checks over every text file in a skill: prompt-override
phrases, private keys and live-format credentials, reverse shells, downloads piped into a shell, credential
access, persistence, unverified package sources, hidden Unicode and opaque base64. Command rules only look at
code (fenced or indented blocks in Markdown, every line of a script), so prose that describes a technique is
not flagged. `check` runs them too (`--skip-security` leaves them out); they do not affect the audit grade. The rules are curated from
[agent-skills-eval](https://github.com/caohaotiantian/agent-skills-eval) and
[SkillClinic](https://github.com/Dongdarealest/SkillClinic), both MIT licensed.

A finding can be allowed, and stays in the report as an info result. In the skill, a comment such as
`# skill-validator: allow SEC020 -- the vendor's documented installer` on the matching line or the line above it
allows warning-level rules only; a marker for an error-level rule (a prompt override, a key, a reverse shell,
hidden Unicode) has no effect and is reported, so a skill cannot hide its own findings. Whoever runs the check can
allow any rule with `--allow-security-rules=SEC001,SEC020`.

## Shell completion

`pantheon-skill-auditor completion <shell>` prints a completion script for `bash`, `zsh`, `fish`, `powershell` or
`elvish`. The validator commands (`validate`, `check`, `probes`, `analyze`) pass their arguments through to the embedded validator, so completion offers the command names but not their flags.

```bash
pantheon-skill-auditor completion zsh > "${fpath[1]}/_pantheon-skill-auditor"
pantheon-skill-auditor completion bash > /etc/bash_completion.d/pantheon-skill-auditor
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
[pantheon-agentic-harness-dev-kit](https://github.com/pantheon-org/pantheon-agentic-harness-dev-kit)
(`pahdk-core`, `pahdk-install`), pinned to a git tag until they are published to crates.io.

## History

Extracted from [pantheon-org/tekhne](https://github.com/pantheon-org/tekhne) with
`git filter-repo` (`crates/skill-validator-rs`, `crates/skill-auditor` and
`skills/agentic-harness/skill-quality-auditor`, now `skills/skill-quality-auditor/`). Commit messages keep
their original `#NNN` references, which point at tekhne pull requests.
