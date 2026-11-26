//! Skill artifact-convention checks, ported from the shell
//! `validate-skill-artifacts.sh`.
//!
//! Two entry points mirror the script's two modes:
//! - [`check_files`]: validate an explicit list of changed files (the
//!   `hk` pre-commit invocation, `validate artifacts <files...>`).
//! - [`check_tree`]: scan the whole `skills/` tree (the no-argument mode).
//!
//! Every finding is an error (the shell only ever raised errors), category
//! `Artifacts`. YAML and JSON validity are checked in-process with
//! `serde_yaml_ng` / `serde_json` rather than shelling out to `yq` / `jq`; the
//! optional `sh -n` and `py_compile` syntax checks are still delegated to those
//! tools when present, matching the shell's `command -v` gating.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::structure::fsutil::{safe_read, ReadError};
use crate::types::{Level, ValidationResult};

const CATEGORY: &str = "Artifacts";

/// Allowed immediate subdirectories of a skill directory.
const ALLOWED_SKILL_DIRS: &[&str] = &[
    "scripts",
    "references",
    "assets",
    "evals",
    "schemas",
    "templates",
];

/// Allowed immediate subdirectories of a skill's `assets/` directory.
const ALLOWED_ASSETS_DIRS: &[&str] = &["templates", "schemas", "requirements", "examples"];

/// The result of an artifact-convention run.
#[derive(Debug, Default)]
pub struct ArtifactReport {
    /// All findings, in emission order.
    pub results: Vec<ValidationResult>,
}

impl ArtifactReport {
    fn error(&mut self, file: &str, message: String) {
        self.results.push(ValidationResult {
            level: Level::Error,
            category: CATEGORY.to_string(),
            message,
            file: file.to_string(),
            line: 0,
        });
    }

    /// Number of error-level findings.
    pub fn errors(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.level == Level::Error)
            .count()
    }
}

/// Validate an explicit list of files (hook mode). For each file the relevant
/// per-file check runs; when a file is a `skills/<domain>/<skill>/SKILL.md`, the
/// enclosing skill directory is also validated. The files must resolve inside
/// the current directory (the repository root, where the hook runs).
pub fn check_files(files: &[PathBuf]) -> ArtifactReport {
    let mut report = ArtifactReport::default();
    let root = Path::new(".");
    for file in files {
        if !file.is_file() {
            continue;
        }
        let rel = file.to_string_lossy().replace('\\', "/");
        check_file(root, &rel, file, &mut report);
        if is_skill_md(&rel) {
            if let Some(dir) = file.parent() {
                check_skill_dir(dir, &mut report);
            }
        }
    }
    report
}

/// Scan the whole `skills/` tree under `root` (no-argument mode): every
/// template/schema/script file is checked, and every `skills/<domain>/<skill>`
/// directory containing a SKILL.md is validated.
pub fn check_tree(root: &Path) -> ArtifactReport {
    let mut report = ArtifactReport::default();

    let mut files = Vec::new();
    collect_files(root, &mut files);
    for file in &files {
        let rel = file.to_string_lossy().replace('\\', "/");
        if rel.contains("/assets/templates/")
            || rel.contains("/assets/schemas/")
            || rel.contains("/scripts/")
        {
            check_file(root, &rel, file, &mut report);
        }
    }

    // skills/<domain>/<skill> directories (exactly two levels under the root).
    if let Ok(domains) = std::fs::read_dir(root) {
        for domain in domains.flatten().filter(is_dir) {
            if let Ok(skills) = std::fs::read_dir(domain.path()) {
                for skill in skills.flatten().filter(is_dir) {
                    if skill.path().join("SKILL.md").is_file() {
                        check_skill_dir(&skill.path(), &mut report);
                    }
                }
            }
        }
    }

    report
}

fn is_dir(entry: &std::fs::DirEntry) -> bool {
    entry.file_type().map(|t| t.is_dir()).unwrap_or(false)
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // Dot-directories (e.g. `scripts/.tools/` holding vendored, gitignored
        // binaries) are skipped: the shell's `**` globbing never descended into
        // hidden path components, so their contents were never scanned. Matches
        // the dot-directory skip already applied to check_subdirs / check_assets.
        let name = entry.file_name();
        if name.to_string_lossy().starts_with('.') {
            continue;
        }
        match entry.file_type() {
            Ok(t) if t.is_dir() => collect_files(&path, out),
            // A symlink is collected so the read guard reports it rather than
            // the scan passing over it; a symlinked directory is not followed.
            Ok(t) if t.is_file() || t.is_symlink() => out.push(path),
            _ => {}
        }
    }
}

/// A `skills/<domain>/<skill>/SKILL.md` path (exactly four components).
fn is_skill_md(rel: &str) -> bool {
    let parts: Vec<&str> = rel.split('/').collect();
    parts.len() == 4 && parts[0] == "skills" && parts[3] == "SKILL.md"
}

/// Dispatch a single file to its convention check by location. The file is
/// read once, through [`safe_read`] with `root` as the containment boundary.
fn check_file(root: &Path, rel: &str, path: &Path, report: &mut ArtifactReport) {
    let check: fn(&str, &Path, Option<&str>, &mut ArtifactReport) =
        if rel.contains("/assets/templates/") {
            check_templates_file
        } else if rel.contains("/assets/schemas/") {
            check_schemas_file
        } else if rel.contains("/scripts/") {
            check_scripts_file
        } else {
            return;
        };
    let Some(text) = read_artifact(root, rel, path, report) else {
        return;
    };
    check(rel, path, text.as_deref(), report);
}

/// Read an artifact through [`safe_read`]. A symlink, a file that resolves
/// outside `root`, or one past the read limit is reported as an error and
/// returns `None`, so no check runs on it. A file that cannot be read as
/// UTF-8 text returns `Some(None)`: the checks treat it as empty, as they
/// did before the guard.
fn read_artifact(
    root: &Path,
    rel: &str,
    path: &Path,
    report: &mut ArtifactReport,
) -> Option<Option<String>> {
    match safe_read(root, path) {
        Ok(text) => Some(Some(text)),
        Err(e @ (ReadError::Unsafe(_) | ReadError::TooLarge(_))) => {
            report.error(rel, e.to_string());
            None
        }
        Err(ReadError::Io(_)) => Some(None),
    }
}

fn check_templates_file(rel: &str, _path: &Path, text: Option<&str>, report: &mut ArtifactReport) {
    if rel.ends_with("/.gitkeep") {
        return;
    }
    if !(rel.ends_with(".yaml") || rel.ends_with(".yml")) {
        return;
    }
    let Some(text) = text else {
        return;
    };
    // Skip files that carry templating placeholders (they are not valid YAML by
    // design): `{{ ... }}`, `{% ... %}`, or `[snake_case]` tokens.
    if text.contains("{{") || text.contains("{%") || has_bracket_token(text) {
        return;
    }
    if serde_yaml_ng::from_str::<serde_yaml_ng::Value>(text).is_err() {
        report.error(rel, format!("{rel} is not valid YAML."));
    }
}

/// True when the text contains a `[lowercase_or_underscore]` placeholder token.
fn has_bracket_token(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j].is_ascii_lowercase() || bytes[j] == b'_') {
                j += 1;
            }
            if j > i + 1 && j < bytes.len() && bytes[j] == b']' {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn check_schemas_file(rel: &str, _path: &Path, text: Option<&str>, report: &mut ArtifactReport) {
    if !rel.ends_with(".schema.json") {
        report.error(
            rel,
            format!("{rel} is in assets/schemas/ but does not use the .schema.json extension."),
        );
        return;
    }
    let Some(text) = text else {
        return;
    };
    if serde_json::from_str::<serde_json::Value>(text).is_err() {
        report.error(rel, format!("{rel} is not valid JSON."));
        return;
    }
    if !declares_schema_url(text) {
        report.error(
            rel,
            format!(r#"{rel} does not declare a JSON Schema "$schema" URL from json-schema.org."#),
        );
    }
}

/// True when the JSON text declares `"$schema": "http(s)://json-schema.org/..."`.
fn declares_schema_url(text: &str) -> bool {
    let Some(idx) = text.find("\"$schema\"") else {
        return false;
    };
    let rest = &text[idx + "\"$schema\"".len()..];
    let rest = rest.trim_start();
    let Some(rest) = rest.strip_prefix(':') else {
        return false;
    };
    let rest = rest.trim_start();
    rest.starts_with("\"http://json-schema.org/") || rest.starts_with("\"https://json-schema.org/")
}

fn check_scripts_file(rel: &str, path: &Path, text: Option<&str>, report: &mut ArtifactReport) {
    if rel.contains("/__pycache__/") || rel.ends_with("/.gitkeep") {
        return;
    }
    if rel.ends_with(".sh") {
        check_shell_script(rel, path, text, report);
    } else if rel.ends_with(".py") {
        check_python_script(rel, path, text, report);
    } else if rel.ends_with(".ts") {
        check_ts_script(rel, path, text, report);
    } else if rel.ends_with(".js") {
        check_js_script(rel, path, text, report);
    } else {
        report.error(
            rel,
            format!(
                "{rel} is in scripts/ but is not a recognised script type (.sh, .py, .ts, .js)."
            ),
        );
    }
}

fn first_line(text: Option<&str>) -> &str {
    text.and_then(|t| t.lines().next()).unwrap_or_default()
}

fn check_shell_script(rel: &str, path: &Path, text: Option<&str>, report: &mut ArtifactReport) {
    let shebang = first_line(text);
    let portable_msg = format!(
        "{rel} must start with portable shebang: #!/usr/bin/env sh (or add '# shell: bash' to allow bash)"
    );
    if shebang == "#!/usr/bin/env sh" {
        // Best-effort POSIX syntax check when `sh` is available.
        if let Some(false) = run_syntax_check("sh", &["-n"], path) {
            report.error(
                rel,
                format!("{rel} failed POSIX shell syntax check (sh -n)."),
            );
        }
    } else if shebang == "#!/usr/bin/env bash" {
        let allows_bash = text.is_some_and(|t| t.lines().any(|l| l.starts_with("# shell: bash")));
        if !allows_bash {
            report.error(rel, portable_msg);
        }
    } else {
        report.error(rel, portable_msg);
    }
}

fn check_python_script(rel: &str, path: &Path, text: Option<&str>, report: &mut ArtifactReport) {
    let shebang = first_line(text);
    if shebang != "#!/usr/bin/env python3" && shebang != "#!/usr/bin/env python" {
        report.error(
            rel,
            format!("{rel} must start with shebang: #!/usr/bin/env python3"),
        );
        return;
    }
    if let Some(false) = run_python_syntax_check(path) {
        report.error(rel, format!("{rel} failed Python syntax check."));
    }
}

fn check_ts_script(rel: &str, _path: &Path, text: Option<&str>, report: &mut ArtifactReport) {
    let shebang = first_line(text);
    let ok = matches!(
        shebang,
        "#!/usr/bin/env bun" | "#!/usr/bin/env -S bun" | "#!/usr/bin/env -S bun run"
    );
    if !ok {
        report.error(
            rel,
            format!("{rel} must start with shebang: #!/usr/bin/env bun"),
        );
    }
}

fn check_js_script(rel: &str, _path: &Path, text: Option<&str>, report: &mut ArtifactReport) {
    let shebang = first_line(text);
    if shebang != "#!/usr/bin/env node" && shebang != "#!/usr/bin/env bun" {
        report.error(
            rel,
            format!("{rel} must start with shebang: #!/usr/bin/env node (or #!/usr/bin/env bun)"),
        );
    }
}

/// Run `<tool> <args...> <path>` when `tool` resolves, returning `Some(true)` on
/// success, `Some(false)` on failure, or `None` when the tool is unavailable
/// (mirrors the shell's `command -v` gating so absent tools never fail a run).
fn run_syntax_check(tool: &str, args: &[&str], path: &Path) -> Option<bool> {
    let output = Command::new(tool).args(args).arg(path).output().ok()?;
    Some(output.status.success())
}

/// Best-effort Python syntax check via `ast.parse`. Unlike the shell's
/// `py_compile`, this writes no bytecode, so it never litters `__pycache__/`
/// directories into the tree. Returns `None` when `python3` is unavailable.
fn run_python_syntax_check(path: &Path) -> Option<bool> {
    let script = "import ast,sys; ast.parse(open(sys.argv[1]).read())";
    let output = Command::new("python3")
        .args(["-c", script])
        .arg(path)
        .output()
        .ok()?;
    Some(output.status.success())
}

/// Validate a single skill directory's structure, SKILL.md size, name match and
/// self-containment.
fn check_skill_dir(dir: &Path, report: &mut ArtifactReport) {
    let dir_rel = dir.to_string_lossy().replace('\\', "/");
    let skill_name = dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    check_subdirs(dir, &dir_rel, report);
    check_assets(dir, &dir_rel, report);
    check_skill_md(dir, &dir_rel, &skill_name, report);
}

/// Immediate subdirectories of the skill dir must be in the allowed set.
fn check_subdirs(dir: &Path, dir_rel: &str, report: &mut ArtifactReport) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten().filter(is_dir) {
        let name = entry.file_name().to_string_lossy().into_owned();
        // Dot-directories (e.g. `.tekhne`) are skipped: the shell's `*/`
        // glob does not match hidden entries, so they were never flagged.
        if name.starts_with('.') {
            continue;
        }
        if !ALLOWED_SKILL_DIRS.contains(&name.as_str()) {
            report.error(
                dir_rel,
                format!(
                    "{dir_rel}: non-standard directory '{name}' (allowed: scripts/, references/, assets/, evals/, schemas/, templates/)"
                ),
            );
        }
    }
}

/// Validate `assets/` subdirectory names and reject loose YAML placed directly
/// in `assets/` (it must live under `assets/templates/`).
fn check_assets(dir: &Path, dir_rel: &str, report: &mut ArtifactReport) {
    let assets = dir.join("assets");
    let Ok(entries) = std::fs::read_dir(&assets) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        // Hidden entries are skipped by the shell's `*/` and `*.yaml` globs.
        if name.starts_with('.') {
            continue;
        }
        if is_dir(&entry) {
            if !ALLOWED_ASSETS_DIRS.contains(&name.as_str()) {
                report.error(
                    dir_rel,
                    format!(
                        "{dir_rel}: non-standard assets/ subdirectory '{name}' (allowed: templates/, schemas/, requirements/, examples/)"
                    ),
                );
            }
        } else if name.ends_with(".yaml") || name.ends_with(".yml") {
            let f = format!("{dir_rel}/assets/{name}");
            report.error(
                &f,
                format!(
                    "{f}: YAML files must be placed in assets/templates/, not directly in assets/"
                ),
            );
        }
    }
}

/// Validate SKILL.md size, frontmatter name match, and self-containment.
fn check_skill_md(dir: &Path, dir_rel: &str, skill_name: &str, report: &mut ArtifactReport) {
    let md_rel = format!("{dir_rel}/SKILL.md");
    let Some(Some(content)) = read_artifact(dir, &md_rel, &dir.join("SKILL.md"), report) else {
        return;
    };

    let line_count = content.lines().count();
    if line_count > 500 {
        report.error(
            &md_rel,
            format!(
                "{md_rel}: {line_count} lines exceeds 500-line limit - move detail to references/"
            ),
        );
    }

    if let Some(name_val) = frontmatter_name(&content) {
        let consolidated = consolidated_skill_name(dir, skill_name);
        let matches = name_val == skill_name || consolidated.as_deref() == Some(name_val.as_str());
        if !name_val.is_empty() && !matches {
            let expected = match &consolidated {
                Some(alt) => format!("directory name '{skill_name}' (or consolidated '{alt}')"),
                None => format!("directory name '{skill_name}'"),
            };
            report.error(
                &md_rel,
                format!("{md_rel}: frontmatter name '{name_val}' does not match {expected}"),
            );
        }
    }

    if contains_parent_ref_outside_code(&content) {
        report.error(
            &md_rel,
            format!("{md_rel}: contains '../' path reference outside code blocks (skills must be self-contained)"),
        );
    }
}

/// The consolidated skill name for a skill nested inside a toolkit directory, or
/// `None` for an ordinary skill. Consolidated skills (generator/validator pairs
/// and multi-skill toolkits like `cfn`, `k8s`, `nx`, `opencode-toolkit`) live in
/// a sub-directory of a shared toolkit directory that carries the tool-level
/// `.tekhne/plugin.json`, and name themselves `<prefix>-<dir>`, so that
/// form is accepted alongside the bare directory name. The prefix is the toolkit
/// directory name with a trailing `-toolkit` removed (`terraform` -> `terraform`,
/// `opencode-toolkit` -> `opencode`). Ordinary skills sit directly under a domain
/// directory, which has no such plugin, so they return `None` and keep the strict
/// `name == directory` rule.
fn consolidated_skill_name(dir: &Path, skill_name: &str) -> Option<String> {
    let parent = dir.parent()?;
    if !parent.join(".tekhne").join("plugin.json").is_file() {
        return None;
    }
    let parent_name = parent.file_name()?.to_string_lossy();
    let prefix = parent_name.strip_suffix("-toolkit").unwrap_or(&parent_name);
    Some(format!("{prefix}-{skill_name}"))
}

/// Extract the first `name:` frontmatter value, stripped of surrounding quotes
/// and whitespace (ports the shell `grep | sed | tr` pipeline).
fn frontmatter_name(content: &str) -> Option<String> {
    let line = content.lines().find(|l| l.starts_with("name:"))?;
    let value = line["name:".len()..].trim();
    let cleaned: String = value
        .chars()
        .filter(|c| *c != '"' && *c != '\'' && *c != ' ')
        .collect();
    Some(cleaned)
}

/// True when `../` appears outside code. Lines from a ```` ``` ```` fence to the
/// next fence (inclusive) are removed first, matching the shell's
/// `sed '/^```/,/^```/d'`. Backtick-delimited inline code spans are also stripped
/// from each surviving line: illustrative snippets like `` `curl .../merge_requests` ``
/// (an ellipsis, not a parent path) are examples, not skill dependencies, so they
/// carry the same "inside code" exemption as fenced blocks.
fn contains_parent_ref_outside_code(content: &str) -> bool {
    let mut in_fence = false;
    for line in content.lines() {
        if line.starts_with("```") {
            // Both the opening and closing fence lines are dropped.
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        if strip_inline_code(line).contains("../") {
            return true;
        }
    }
    false
}

/// Remove backtick-delimited inline code spans from a single line, leaving only
/// prose. An unterminated backtick drops the remainder of the line (matching how
/// Markdown renders a dangling span as literal text we conservatively ignore).
fn strip_inline_code(line: &str) -> String {
    let mut out = String::new();
    let mut in_code = false;
    for ch in line.chars() {
        if ch == '`' {
            in_code = !in_code;
            continue;
        }
        if !in_code {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn read(path: &Path) -> Option<String> {
        fs::read_to_string(path).ok()
    }

    fn write(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    #[test]
    fn schema_extension_and_url_enforced() {
        let dir = tempdir().unwrap();
        let bad_ext = dir.path().join("skills/d/s/assets/schemas/thing.json");
        write(
            &bad_ext,
            r#"{"$schema":"https://json-schema.org/draft/2020-12/schema"}"#,
        );
        let mut report = ArtifactReport::default();
        check_schemas_file(
            "skills/d/s/assets/schemas/thing.json",
            &bad_ext,
            read(&bad_ext).as_deref(),
            &mut report,
        );
        assert_eq!(report.errors(), 1);
        assert!(report.results[0].message.contains(".schema.json extension"));
    }

    #[test]
    fn schema_missing_url_flagged() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("x.schema.json");
        write(&f, r#"{"type":"object"}"#);
        let mut report = ArtifactReport::default();
        check_schemas_file(
            "skills/d/s/assets/schemas/x.schema.json",
            &f,
            read(&f).as_deref(),
            &mut report,
        );
        assert_eq!(report.errors(), 1);
        assert!(report.results[0].message.contains("$schema"));
    }

    #[test]
    fn valid_schema_passes() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("x.schema.json");
        write(
            &f,
            r#"{"$schema": "https://json-schema.org/draft-07/schema#","type":"object"}"#,
        );
        let mut report = ArtifactReport::default();
        check_schemas_file(
            "skills/d/s/assets/schemas/x.schema.json",
            &f,
            read(&f).as_deref(),
            &mut report,
        );
        assert_eq!(report.errors(), 0);
    }

    #[test]
    fn unknown_script_type_flagged() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("tool.rb");
        write(&f, "puts 1\n");
        let mut report = ArtifactReport::default();
        check_scripts_file(
            "skills/d/s/scripts/tool.rb",
            &f,
            read(&f).as_deref(),
            &mut report,
        );
        assert_eq!(report.errors(), 1);
        assert!(report.results[0].message.contains("recognised script type"));
    }

    #[test]
    fn bad_shell_shebang_flagged() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("go.sh");
        write(&f, "#!/bin/bash\necho hi\n");
        let mut report = ArtifactReport::default();
        check_scripts_file(
            "skills/d/s/scripts/go.sh",
            &f,
            read(&f).as_deref(),
            &mut report,
        );
        assert_eq!(report.errors(), 1);
        assert!(report.results[0].message.contains("portable shebang"));
    }

    #[test]
    fn bash_shebang_with_marker_allowed() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("go.sh");
        write(&f, "#!/usr/bin/env bash\n# shell: bash\necho hi\n");
        let mut report = ArtifactReport::default();
        check_scripts_file(
            "skills/d/s/scripts/go.sh",
            &f,
            read(&f).as_deref(),
            &mut report,
        );
        assert_eq!(report.errors(), 0);
    }

    #[test]
    fn template_placeholder_yaml_skipped() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("tmpl.yaml");
        write(&f, "name: {{ value }}\n:::not valid yaml:::\n");
        let mut report = ArtifactReport::default();
        check_templates_file(
            "skills/d/s/assets/templates/tmpl.yaml",
            &f,
            read(&f).as_deref(),
            &mut report,
        );
        assert_eq!(report.errors(), 0);
    }

    #[test]
    fn invalid_template_yaml_flagged() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("tmpl.yaml");
        write(&f, "key: value\n\tbad: indent\n  - nope\n");
        let mut report = ArtifactReport::default();
        check_templates_file(
            "skills/d/s/assets/templates/tmpl.yaml",
            &f,
            read(&f).as_deref(),
            &mut report,
        );
        assert_eq!(report.errors(), 1);
    }

    #[test]
    fn non_standard_skill_subdir_flagged() {
        let dir = tempdir().unwrap();
        let skill = dir.path().join("skills/d/my-skill");
        write(&skill.join("SKILL.md"), "---\nname: my-skill\n---\nBody\n");
        fs::create_dir_all(skill.join("weird")).unwrap();
        let mut report = ArtifactReport::default();
        check_skill_dir(&skill, &mut report);
        assert_eq!(report.errors(), 1);
        assert!(report.results[0]
            .message
            .contains("non-standard directory 'weird'"));
    }

    #[test]
    fn dot_directories_are_not_flagged() {
        // `.tekhne` (and any hidden dir) is skipped, matching the shell's
        // `*/` glob which never matched dot-directories.
        let dir = tempdir().unwrap();
        let skill = dir.path().join("skills/d/my-skill");
        write(&skill.join("SKILL.md"), "---\nname: my-skill\n---\nBody\n");
        fs::create_dir_all(skill.join(".tekhne")).unwrap();
        write(&skill.join(".tekhne/plugin.json"), "{}\n");
        let mut report = ArtifactReport::default();
        check_skill_dir(&skill, &mut report);
        assert_eq!(report.errors(), 0, "{:?}", report.results);
    }

    #[test]
    fn name_mismatch_flagged() {
        let dir = tempdir().unwrap();
        let skill = dir.path().join("skills/d/my-skill");
        write(
            &skill.join("SKILL.md"),
            "---\nname: wrong-name\n---\nBody\n",
        );
        let mut report = ArtifactReport::default();
        check_skill_dir(&skill, &mut report);
        assert_eq!(report.errors(), 1);
        assert!(report.results[0]
            .message
            .contains("does not match directory name"));
    }

    #[test]
    fn consolidated_generator_validator_not_flagged() {
        // A `<tool>/{generator,validator}` pair names itself `<tool>-generator` /
        // `<tool>-validator` while living in a `generator` / `validator` directory
        // under the shared `<tool>` dir, which carries the tool-level
        // `.tekhne/plugin.json`. Both are correctly structured and must not
        // trip the name-vs-directory rule (issue #243).
        let dir = tempdir().unwrap();
        let toolkit = dir.path().join("skills/infrastructure/terraform");
        write(&toolkit.join(".tekhne/plugin.json"), "{}");
        for (sub, name) in [
            ("generator", "terraform-generator"),
            ("validator", "terraform-validator"),
        ] {
            let skill = toolkit.join(sub);
            write(
                &skill.join("SKILL.md"),
                &format!("---\nname: {name}\n---\nBody\n"),
            );
            let mut report = ArtifactReport::default();
            check_skill_dir(&skill, &mut report);
            assert_eq!(report.errors(), 0, "{sub}: {:?}", report.results);
        }
    }

    #[test]
    fn consolidated_toolkit_names_not_flagged() {
        // Multi-skill toolkits prefix each skill with the toolkit name, and a
        // trailing `-toolkit` is dropped from the prefix (issue #260).
        let dir = tempdir().unwrap();
        for (rel, name) in [
            (
                "skills/infrastructure/cfn/behavior-validator",
                "cfn-behavior-validator",
            ),
            (
                "skills/infrastructure/k8s/yaml-generator",
                "k8s-yaml-generator",
            ),
            (
                "skills/repository-mgmt/nx/biome-integration",
                "nx-biome-integration",
            ),
            (
                "skills/agentic-harness/opencode-toolkit/build-plugins",
                "opencode-build-plugins",
            ),
        ] {
            let skill = dir.path().join(rel);
            write(&skill.parent().unwrap().join(".tekhne/plugin.json"), "{}");
            write(
                &skill.join("SKILL.md"),
                &format!("---\nname: {name}\n---\nBody\n"),
            );
            let mut report = ArtifactReport::default();
            check_skill_dir(&skill, &mut report);
            assert_eq!(report.errors(), 0, "{rel}: {:?}", report.results);
        }
    }

    #[test]
    fn non_toolkit_prefixed_name_still_flagged() {
        // Robustness: without a tool-level plugin the parent is not a toolkit, so a
        // `<parent>-<dir>` name is not a valid consolidated form and is still an
        // error. The exemption must not silently accept prefixed names anywhere.
        let dir = tempdir().unwrap();
        let skill = dir.path().join("skills/development/commanderjs");
        write(
            &skill.join("SKILL.md"),
            "---\nname: development-commanderjs\n---\nBody\n",
        );
        let mut report = ArtifactReport::default();
        check_skill_dir(&skill, &mut report);
        assert_eq!(report.errors(), 1, "{:?}", report.results);
    }

    #[test]
    fn consolidated_wrong_name_still_flagged() {
        // The consolidated exemption only accepts `<prefix>-<dir>`: a genuinely
        // wrong name in a generator/validator directory is still an error, and the
        // message surfaces the accepted consolidated form.
        let dir = tempdir().unwrap();
        let toolkit = dir.path().join("skills/infrastructure/terraform");
        write(&toolkit.join(".tekhne/plugin.json"), "{}");
        let skill = toolkit.join("generator");
        write(
            &skill.join("SKILL.md"),
            "---\nname: terraform-gen\n---\nBody\n",
        );
        let mut report = ArtifactReport::default();
        check_skill_dir(&skill, &mut report);
        assert_eq!(report.errors(), 1);
        assert!(report.results[0]
            .message
            .contains("consolidated 'terraform-generator'"));
    }

    #[test]
    fn parent_ref_outside_code_flagged() {
        let content = "---\nname: s\n---\nSee ../other/file for details.\n";
        assert!(contains_parent_ref_outside_code(content));
    }

    #[test]
    fn parent_ref_inside_code_ignored() {
        let content = "---\nname: s\n---\n```sh\ncat ../foo\n```\nClean prose.\n";
        assert!(!contains_parent_ref_outside_code(content));
    }

    #[test]
    fn parent_ref_inside_inline_code_ignored() {
        // An ellipsis inside an inline code span (`curl .../merge_requests`) is an
        // illustrative snippet, not a parent-path dependency: it must not be flagged.
        let content = "---\nname: s\n---\nUse `curl .../merge_requests` here.\n";
        assert!(!contains_parent_ref_outside_code(content));
    }

    #[test]
    fn parent_ref_in_prose_still_flagged_with_inline_code_present() {
        // A real `../` in prose is still caught even when an inline span sits on the
        // same line, so the inline-code exemption cannot mask a genuine reference.
        let content = "---\nname: s\n---\nSee ../other and run `ls` now.\n";
        assert!(contains_parent_ref_outside_code(content));
    }

    #[test]
    fn tree_scan_skips_dot_directories() {
        // A vendored binary under `scripts/.tools/` (gitignored in practice) must
        // not be flagged as an unrecognised script type: the whole-tree scan skips
        // hidden path components, matching the shell's `**` globbing.
        let dir = tempdir().unwrap();
        let skill = dir.path().join("skills/d/my-skill");
        write(&skill.join("SKILL.md"), "---\nname: my-skill\n---\nBody\n");
        write(&skill.join("scripts/.tools/actionlint"), "binary-ish\n");
        let report = check_tree(&dir.path().join("skills"));
        assert_eq!(report.errors(), 0, "{:?}", report.results);
    }

    #[cfg(unix)]
    #[test]
    fn tree_scan_refuses_a_symlinked_script() {
        let dir = tempdir().unwrap();
        let outside = dir.path().join("outside.sh");
        write(&outside, "#!/usr/bin/env sh\necho hi\n");
        let skill = dir.path().join("skills/d/my-skill");
        write(&skill.join("SKILL.md"), "---\nname: my-skill\n---\nBody\n");
        fs::create_dir_all(skill.join("scripts")).unwrap();
        std::os::unix::fs::symlink(&outside, skill.join("scripts/go.sh")).unwrap();
        let report = check_tree(&dir.path().join("skills"));
        assert_eq!(report.errors(), 1, "{:?}", report.results);
        assert!(report.results[0].message.contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn hook_mode_refuses_a_file_outside_the_root() {
        let dir = tempdir().unwrap();
        let outside = dir.path().join("outside.sh");
        write(&outside, "#!/usr/bin/env sh\necho hi\n");
        let root = dir.path().join("repo");
        let scripts = root.join("skills/d/s/scripts");
        fs::create_dir_all(root.join("skills/d/s")).unwrap();
        // The directory, not the file, is the symlink: the file is regular
        // but resolves outside the root.
        std::os::unix::fs::symlink(dir.path(), &scripts).unwrap();
        let mut report = ArtifactReport::default();
        check_file(
            &root,
            "skills/d/s/scripts/outside.sh",
            &scripts.join("outside.sh"),
            &mut report,
        );
        assert_eq!(report.errors(), 1, "{:?}", report.results);
        assert!(report.results[0]
            .message
            .contains("outside the skill directory"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_skill_md_is_refused() {
        let dir = tempdir().unwrap();
        let outside = dir.path().join("elsewhere.md");
        write(&outside, "---\nname: wrong\n---\nSee ../x\n");
        let skill = dir.path().join("skills/d/my-skill");
        fs::create_dir_all(&skill).unwrap();
        std::os::unix::fs::symlink(&outside, skill.join("SKILL.md")).unwrap();
        let mut report = ArtifactReport::default();
        check_skill_dir(&skill, &mut report);
        // One refusal, not the name and parent-reference findings of the target.
        assert_eq!(report.errors(), 1, "{:?}", report.results);
        assert!(report.results[0].message.contains("not a regular file"));
    }

    #[test]
    fn loose_yaml_in_assets_flagged() {
        let dir = tempdir().unwrap();
        let skill = dir.path().join("skills/d/my-skill");
        write(&skill.join("SKILL.md"), "---\nname: my-skill\n---\nBody\n");
        write(&skill.join("assets/loose.yaml"), "key: value\n");
        let mut report = ArtifactReport::default();
        check_skill_dir(&skill, &mut report);
        assert!(report
            .results
            .iter()
            .any(|r| r.message.contains("must be placed in assets/templates/")));
    }
}
