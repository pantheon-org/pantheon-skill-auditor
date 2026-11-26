//! Skill discovery below a path (Go `skillcheck.DiscoverSkills`, upstream
//! v1.8.0).
//!
//! A path holding `SKILL.md` is a single skill and nothing below it is
//! examined. Otherwise its subdirectories are searched breadth-first, up to
//! `max_depth` levels below it (1 means the immediate subdirectories), and
//! every directory holding a `SKILL.md` is a skill. A skill's own subtree is
//! not searched, so a `SKILL.md` inside a skill's references or examples is
//! not a second skill. Hidden directories, `node_modules` and `__pycache__`
//! are skipped.
//!
//! Symlinks to directories are followed, so a skills directory assembled
//! from links works. Each real directory is examined once, which makes
//! cycles and aliases harmless. The scan lists at most [`MAX_DISCOVERY_DIRS`]
//! directories and reports `truncated` when it had to stop; it is
//! breadth-first, so shallow skills are found before a large or linked
//! subtree can use up that budget. The bounds follow the agentskills.io
//! client guide ("max depth of 4-6 levels, max 2000 directories").

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};

use crate::types::SkillMode;

/// How many directory levels below the given path are searched by default.
pub const DEFAULT_MAX_DEPTH: usize = 6;

/// The most directories one scan lists before it stops.
pub const MAX_DISCOVERY_DIRS: usize = 2000;

/// Directory names that never hold skills and can be large enough to use up
/// the budget. Hidden directories are skipped by their leading dot.
const SKIP_DIRS: &[&str] = &["node_modules", "__pycache__"];

/// The result of [`discover_skills`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    /// Single skill, several skills, or none.
    pub mode: SkillMode,
    /// The skill directories, sorted, as reached from the given path. For a
    /// single skill it is the given path; for none it is empty.
    pub dirs: Vec<PathBuf>,
    /// The scan stopped at [`MAX_DISCOVERY_DIRS`] with directories left, so
    /// skills below that point were missed.
    pub truncated: bool,
}

/// Find the skills at or below `root`, searching `max_depth` levels deep.
pub fn discover_skills(root: &Path, max_depth: usize) -> Discovery {
    discover(root, max_depth, MAX_DISCOVERY_DIRS)
}

fn none(truncated: bool) -> Discovery {
    Discovery {
        mode: SkillMode::NoSkill,
        dirs: Vec::new(),
        truncated,
    }
}

fn has_skill_file(dir: &Path) -> bool {
    // Follows a symlink, like Go's `os.Stat`.
    dir.join("SKILL.md").exists()
}

fn discover(root: &Path, max_depth: usize, max_dirs: usize) -> Discovery {
    if has_skill_file(root) {
        return Discovery {
            mode: SkillMode::SingleSkill,
            dirs: vec![root.to_path_buf()],
            truncated: false,
        };
    }
    if max_depth < 1 {
        return none(false);
    }
    // Identity keys are absolute and symlink-resolved, so a relative root and
    // a link to an absolute target cannot name one directory twice.
    // Reported paths stay as reached from `root`.
    let Ok(real_root) = std::fs::canonicalize(root) else {
        return none(false);
    };
    let mut visited: HashSet<PathBuf> = HashSet::from([real_root.clone()]);
    let mut queue: VecDeque<(PathBuf, PathBuf, usize)> =
        VecDeque::from([(root.to_path_buf(), real_root, 0)]);
    let mut skills = Vec::new();
    let mut listed = 0;
    let mut truncated = false;

    while let Some((path, real, depth)) = queue.pop_front() {
        if listed >= max_dirs {
            truncated = true;
            break;
        }
        listed += 1;
        for (name, is_dir, is_link) in sorted_entries(&path) {
            if name.starts_with('.') || SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            let sub = path.join(&name);
            let sub_real = if is_dir {
                real.join(&name)
            } else if is_link {
                // Follow a link, but only into a directory that exists.
                match std::fs::canonicalize(real.join(&name)) {
                    Ok(resolved) if resolved.is_dir() => resolved,
                    _ => continue,
                }
            } else {
                continue;
            };
            if !visited.insert(sub_real.clone()) {
                continue;
            }
            if has_skill_file(&sub) {
                skills.push(sub);
            } else if depth + 1 < max_depth {
                queue.push_back((sub, sub_real, depth + 1));
            }
        }
    }

    if skills.is_empty() {
        return none(truncated);
    }
    // As strings, like Go's `sort.Strings`: `a-b` sorts before `a/b`, where
    // a component-wise `PathBuf` order would put `a/b` first.
    skills.sort_by(|a, b| a.as_os_str().cmp(b.as_os_str()));
    Discovery {
        mode: SkillMode::MultiSkill,
        dirs: skills,
        truncated,
    }
}

/// A directory's entries as (name, is a directory, is a symlink), sorted by
/// name like Go's `os.ReadDir`. The types are the entries' own, not their
/// targets'. Empty when the directory cannot be read.
fn sorted_entries(dir: &Path) -> Vec<(String, bool, bool)> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<(String, bool, bool)> = rd
        .flatten()
        .filter_map(|e| {
            let t = e.file_type().ok()?;
            Some((
                e.file_name().to_string_lossy().into_owned(),
                t.is_dir(),
                t.is_symlink(),
            ))
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[cfg(test)]
mod tests {
    // Ported from upstream v1.8.0 `skillcheck/validator_test.go`.
    use super::*;
    use std::fs;

    fn skill(dir: &Path) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("SKILL.md"), "---\nname: s\n---\n").unwrap();
    }

    fn dirs(d: &Discovery) -> Vec<PathBuf> {
        d.dirs.clone()
    }

    #[test]
    fn two_levels_sorted() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        skill(&r.join("cuopt/cuopt-developer"));
        skill(&r.join("Megatron-Bridge/bump-base-image"));
        skill(&r.join("Megatron-Bridge/update-golden-values"));
        let d = discover_skills(r, DEFAULT_MAX_DEPTH);
        assert_eq!(d.mode, SkillMode::MultiSkill);
        assert_eq!(
            dirs(&d),
            vec![
                r.join("Megatron-Bridge/bump-base-image"),
                r.join("Megatron-Bridge/update-golden-values"),
                r.join("cuopt/cuopt-developer"),
            ]
        );
        assert!(!d.truncated);
    }

    #[test]
    fn sorted_as_strings() {
        let t = tempfile::tempdir().unwrap();
        skill(&t.path().join("a/b"));
        skill(&t.path().join("a-b"));
        let d = discover_skills(t.path(), DEFAULT_MAX_DEPTH);
        assert_eq!(dirs(&d), vec![t.path().join("a-b"), t.path().join("a/b")]);
    }

    #[test]
    fn single_skill_is_not_searched_below() {
        let t = tempfile::tempdir().unwrap();
        skill(t.path());
        skill(&t.path().join("examples/nested"));
        let d = discover_skills(t.path(), DEFAULT_MAX_DEPTH);
        assert_eq!(d.mode, SkillMode::SingleSkill);
        assert_eq!(dirs(&d), vec![t.path().to_path_buf()]);
    }

    #[test]
    fn depth_bound() {
        let t = tempfile::tempdir().unwrap();
        let at =
            |depth: usize| (1..=depth).fold(t.path().to_path_buf(), |p, i| p.join(format!("l{i}")));
        skill(&at(DEFAULT_MAX_DEPTH));
        skill(&at(DEFAULT_MAX_DEPTH - 1).join("other/x")); // depth 7
        let d = discover_skills(t.path(), DEFAULT_MAX_DEPTH);
        assert_eq!(dirs(&d), vec![at(DEFAULT_MAX_DEPTH)]);
        assert!(!d.truncated, "a depth cutoff is not a truncation");
        assert_eq!(discover_skills(t.path(), 1).mode, SkillMode::NoSkill);
        assert_eq!(
            discover_skills(&at(DEFAULT_MAX_DEPTH), 0).mode,
            SkillMode::SingleSkill
        );
        assert_eq!(discover_skills(t.path(), 0).mode, SkillMode::NoSkill);
    }

    #[test]
    fn does_not_descend_into_a_skill() {
        let t = tempfile::tempdir().unwrap();
        skill(&t.path().join("skill"));
        skill(&t.path().join("skill/examples/nested"));
        let d = discover_skills(t.path(), DEFAULT_MAX_DEPTH);
        assert_eq!(dirs(&d), vec![t.path().join("skill")]);
    }

    #[test]
    fn skips_hidden_and_dependency_dirs() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        skill(&r.join("group/.hidden/skill"));
        skill(&r.join("node_modules/pkg/skill"));
        skill(&r.join("__pycache__/skill"));
        skill(&r.join("web/node_modules/skill"));
        skill(&r.join("web/skill"));
        let d = discover_skills(r, DEFAULT_MAX_DEPTH);
        assert_eq!(dirs(&d), vec![r.join("web/skill")]);
    }

    #[test]
    fn directory_budget() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        for i in 0..50 {
            fs::create_dir_all(r.join(format!("a{i:02}/sub"))).unwrap();
        }
        skill(&r.join("shallow"));
        skill(&r.join("zgroup/deep"));
        let d = discover(r, DEFAULT_MAX_DEPTH, 20);
        assert_eq!(dirs(&d), vec![r.join("shallow")]);
        assert!(d.truncated);
        let d = discover(r, DEFAULT_MAX_DEPTH, MAX_DISCOVERY_DIRS);
        assert_eq!(d.dirs.len(), 2);
        assert!(!d.truncated);
    }

    #[cfg(unix)]
    mod symlinks {
        use super::*;
        use std::os::unix::fs::symlink;

        #[test]
        fn cycles_are_harmless() {
            let t = tempfile::tempdir().unwrap();
            let r = t.path();
            skill(&r.join("team/skill"));
            symlink(r, r.join("loop")).unwrap();
            symlink("..", r.join("team/up")).unwrap();
            let d = discover_skills(r, DEFAULT_MAX_DEPTH);
            assert_eq!(dirs(&d), vec![r.join("team/skill")]);
            assert!(!d.truncated);
        }

        #[test]
        fn an_alias_is_reported_once() {
            let t = tempfile::tempdir().unwrap();
            skill(&t.path().join("real"));
            symlink(t.path().join("real"), t.path().join("alias")).unwrap();
            assert_eq!(discover_skills(t.path(), DEFAULT_MAX_DEPTH).dirs.len(), 1);
        }

        #[test]
        fn follows_a_link_to_a_skill_outside_the_root() {
            let outside = tempfile::tempdir().unwrap();
            skill(&outside.path().join("shared"));
            let t = tempfile::tempdir().unwrap();
            fs::create_dir_all(t.path().join("team")).unwrap();
            symlink(outside.path().join("shared"), t.path().join("team/shared")).unwrap();
            let d = discover_skills(t.path(), DEFAULT_MAX_DEPTH);
            assert_eq!(dirs(&d), vec![t.path().join("team/shared")]);
        }

        #[test]
        fn broken_links_and_file_links_are_ignored() {
            let t = tempfile::tempdir().unwrap();
            let r = t.path();
            skill(&r.join("skill"));
            symlink(r.join("missing"), r.join("dangling")).unwrap();
            symlink(r.join("skill/SKILL.md"), r.join("filelink")).unwrap();
            assert_eq!(
                dirs(&discover_skills(r, DEFAULT_MAX_DEPTH)),
                vec![r.join("skill")]
            );
        }

        #[test]
        fn a_linked_large_tree_cannot_starve_a_sibling() {
            let big = tempfile::tempdir().unwrap();
            for i in 0..30 {
                fs::create_dir_all(big.path().join(format!("d{i:02}/x/y"))).unwrap();
            }
            let t = tempfile::tempdir().unwrap();
            symlink(big.path(), t.path().join("aaa-link")).unwrap();
            skill(&t.path().join("team/skill"));
            let d = discover(t.path(), DEFAULT_MAX_DEPTH, 40);
            assert_eq!(dirs(&d), vec![t.path().join("team/skill")]);
            assert!(d.truncated);
        }
    }
}
