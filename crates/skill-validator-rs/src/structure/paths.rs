//! Skill-relative path options (Go `structure/paths.go`, upstream v1.8.0):
//! the values of `--allow-nested-paths` and `--exclude-token-paths`.

/// Normalise user-supplied skill-relative paths, dropping duplicates and
/// failing on the first invalid one (Go `NormalizeRelativePaths`). The CLI
/// calls this so a bad value is a usage error.
pub fn normalize_relative_paths(paths: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::with_capacity(paths.len());
    for raw in paths {
        let value = normalize_relative_path(raw)?;
        if !out.contains(&value) {
            out.push(value);
        }
    }
    Ok(out)
}

/// Like [`normalize_relative_paths`], but skips invalid paths (Go
/// `normalizedRelativePaths`): the checks accept options a library caller
/// built without the CLI's validation.
pub fn normalized_relative_paths(paths: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(paths.len());
    for value in paths.iter().filter_map(|p| normalize_relative_path(p).ok()) {
        if !out.contains(&value) {
            out.push(value);
        }
    }
    out
}

/// Normalise one path: backslashes become slashes, surrounding space is
/// trimmed, and the result is cleaned like Go's `path.Clean`. It must be
/// relative, below the skill root and not escape it.
pub fn normalize_relative_path(raw: &str) -> Result<String, String> {
    let value = raw.replace('\\', "/");
    let value = value.trim();
    if value.is_empty() {
        return Err("path must not be empty".to_string());
    }
    if value.starts_with('/') || has_windows_volume(value) {
        return Err(format!("{raw:?} must be relative to the skill root"));
    }
    let value = clean(value);
    if value == "." {
        return Err(format!("{raw:?} must identify a path below the skill root"));
    }
    if value == ".." || value.starts_with("../") {
        return Err(format!("{raw:?} escapes the skill root"));
    }
    Ok(value)
}

/// Go `path.Clean` for a relative path: drop empty and `.` segments and
/// resolve `..` against the segment before it; a leading `..` is kept.
fn clean(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." if parts.last().is_some_and(|p| *p != "..") => {
                parts.pop();
            }
            _ => parts.push(seg),
        }
    }
    if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join("/")
    }
}

fn has_windows_volume(value: &str) -> bool {
    let b = value.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

/// Whether `candidate` is `subtree` or lies under it (Go `pathInSubtree`).
pub fn path_in_subtree(candidate: &str, subtree: &str) -> bool {
    candidate == subtree
        || candidate
            .strip_prefix(subtree)
            .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_and_dedupes() {
        let got = normalize_relative_paths(&[
            " assets\\components ".to_string(),
            "./assets/components/".to_string(),
            "site/../docs".to_string(),
        ])
        .unwrap();
        assert_eq!(got, vec!["assets/components", "docs"]);
    }

    #[test]
    fn rejects_paths_outside_or_at_the_root() {
        for bad in [
            "",
            "  ",
            "/abs",
            "C:/x",
            "c:x",
            ".",
            "a/..",
            "..",
            "../x",
            "a/../../x",
        ] {
            assert!(normalize_relative_path(bad).is_err(), "{bad:?}");
        }
        assert!(normalize_relative_paths(&["ok".into(), "../no".into()]).is_err());
        assert_eq!(
            normalized_relative_paths(&["ok".into(), "../no".into()]),
            vec!["ok"]
        );
    }

    #[test]
    fn subtree_matches_on_segments() {
        assert!(path_in_subtree("site", "site"));
        assert!(path_in_subtree("site/a/b.md", "site"));
        assert!(!path_in_subtree("sitemap", "site"));
        assert!(!path_in_subtree("docs/site", "site"));
    }
}
