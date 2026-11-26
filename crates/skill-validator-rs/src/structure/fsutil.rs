//! Shared filesystem helpers for the structure checks. Iteration is sorted to
//! match Go's `os.ReadDir` / `filepath.Walk` lexical ordering, so token counts
//! and orphan walks are deterministic.
//!
//! Every file read from a skill package goes through [`safe_read`] or
//! [`safe_read_n`] (Go `util.SafeReadFile` / `SafeReadFileN`, upstream v1.6.0
//! and v1.6.2): a skill is untrusted input, so a symlink, device or pipe is
//! refused, a path that resolves outside the skill is refused, and no file is
//! read past [`MAX_SKILL_FILE_BYTES`].

use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

/// The most the validator reads from any single file in a skill package
/// (Go `util.MaxSkillFileBytes`).
pub const MAX_SKILL_FILE_BYTES: u64 = 8 << 20;

/// Why a skill file was not read.
#[derive(Debug)]
pub enum ReadError {
    /// Not a regular file, or it resolves outside the skill directory.
    Unsafe(String),
    /// Larger than [`MAX_SKILL_FILE_BYTES`] (only from [`safe_read`]).
    TooLarge(String),
    /// Missing, unreadable, or not valid UTF-8.
    Io(String),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::Unsafe(m) | ReadError::TooLarge(m) | ReadError::Io(m) => f.write_str(m),
        }
    }
}

/// Render a byte count for messages: whole MiB or KiB where exact, plain
/// bytes otherwise (Go `util.FormatByteSize`).
pub fn format_byte_size(n: u64) -> String {
    if n >= 1 << 20 && n.is_multiple_of(1 << 20) {
        format!("{} MiB", n >> 20)
    } else if n >= 1 << 10 && n.is_multiple_of(1 << 10) {
        format!("{} KiB", n >> 10)
    } else {
        format!("{n} bytes")
    }
}

/// Whether `path`, with every symlink resolved, stays inside `root`
/// (Go `util.ResolvesWithin`). The path must exist.
pub fn resolves_within(root: &Path, path: &Path) -> std::io::Result<bool> {
    let root = std::fs::canonicalize(root)?;
    let resolved = std::fs::canonicalize(path)?;
    Ok(resolved.starts_with(&root))
}

/// Whether `path` is a regular file, without following a symlink.
pub fn is_regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file())
}

/// Read at most `limit` bytes of `path`, a file inside the skill rooted at
/// `root`, and report whether the file had more. The file must be a regular
/// file (not a symlink) that resolves inside `root`. A truncated read is cut
/// back to the last whole UTF-8 character; otherwise the text must be valid
/// UTF-8, as `read_to_string` required before.
pub fn safe_read_n(root: &Path, path: &Path, limit: u64) -> Result<(String, bool), ReadError> {
    let shown = path.display();
    let meta = std::fs::symlink_metadata(path).map_err(|e| ReadError::Io(e.to_string()))?;
    if !meta.file_type().is_file() {
        return Err(ReadError::Unsafe(format!(
            "refusing to read unsafe file: {shown} is not a regular file"
        )));
    }
    if !resolves_within(root, path).map_err(|e| ReadError::Io(e.to_string()))? {
        return Err(ReadError::Unsafe(format!(
            "refusing to read unsafe file: {shown} resolves outside the skill directory"
        )));
    }
    let file = std::fs::File::open(path).map_err(|e| ReadError::Io(e.to_string()))?;
    let mut data = Vec::new();
    // One byte past the limit shows truncation without a second stat.
    file.take(limit + 1)
        .read_to_end(&mut data)
        .map_err(|e| ReadError::Io(e.to_string()))?;
    let truncated = data.len() as u64 > limit;
    if truncated {
        data.truncate(limit as usize);
    }
    match String::from_utf8(data) {
        Ok(text) => Ok((text, truncated)),
        Err(e) if truncated => {
            let valid = e.utf8_error().valid_up_to();
            let mut bytes = e.into_bytes();
            bytes.truncate(valid);
            Ok((String::from_utf8(bytes).unwrap_or_default(), true))
        }
        Err(e) => Err(ReadError::Io(e.to_string())),
    }
}

/// Read a whole skill file, refusing one larger than [`MAX_SKILL_FILE_BYTES`]
/// with [`ReadError::TooLarge`] (Go `util.SafeReadFile`).
pub fn safe_read(root: &Path, path: &Path) -> Result<String, ReadError> {
    let (text, truncated) = safe_read_n(root, path, MAX_SKILL_FILE_BYTES)?;
    if truncated {
        return Err(ReadError::TooLarge(format!(
            "file exceeds the read limit: {} is larger than {}",
            path.display(),
            format_byte_size(MAX_SKILL_FILE_BYTES)
        )));
    }
    Ok(text)
}

const BINARY_EXTENSIONS: &[&str] = &[
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp", ".pdf", ".doc", ".docx",
    ".xls", ".xlsx", ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib",
    ".bin", ".mp3", ".mp4", ".wav", ".avi", ".mov", ".woff", ".woff2", ".ttf", ".eot", ".otf",
];

/// A directory entry: name, full path, and file type. Like Go's
/// `os.DirEntry`, the type is the entry's own, so a symlink to a directory is
/// neither `is_dir` nor `is_regular`.
pub struct Entry {
    /// The base name of the entry.
    pub name: String,
    /// The full path to the entry.
    pub path: PathBuf,
    /// Whether the entry is a directory (not a symlink to one).
    pub is_dir: bool,
    /// Whether the entry is a regular file (not a symlink, device or pipe).
    pub is_regular: bool,
}

/// Read a directory's entries sorted lexically by name (Go `os.ReadDir`).
/// Returns an empty vector when the directory cannot be read.
pub fn read_dir_sorted(dir: &Path) -> Vec<Entry> {
    let mut entries = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return entries;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let path = e.path();
        let (is_dir, is_regular) = e
            .file_type()
            .map(|t| (t.is_dir(), t.is_file()))
            .unwrap_or((false, false));
        entries.push(Entry {
            name,
            path,
            is_dir,
            is_regular,
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    entries
}

/// Walk files under `root` in Go `filepath.Walk` order (lexical, pre-order),
/// skipping hidden files and hidden subdirectories. Like `filepath.Walk`, a
/// symlinked directory is not descended into, so a link cycle cannot loop.
pub fn walk_files(root: &Path, out: &mut Vec<PathBuf>) {
    for e in read_dir_sorted(root) {
        if e.name.starts_with('.') {
            continue;
        }
        if e.is_dir {
            walk_files(&e.path, out);
        } else {
            out.push(e.path);
        }
    }
}

/// The lower-cased extension including the dot (Go `filepath.Ext` + `ToLower`).
pub fn ext_lower(name: &str) -> String {
    match name.rfind('.') {
        Some(i) => name[i..].to_lowercase(),
        None => String::new(),
    }
}

/// Whether `name`'s extension is in the binary skip-list.
pub fn is_binary_ext(name: &str) -> bool {
    BINARY_EXTENSIONS.contains(&ext_lower(name).as_str())
}

/// A file is "text" when its extension is not in the binary list
/// (Go `structure.isTextFile`).
pub fn is_text_file(name: &str) -> bool {
    !is_binary_ext(name)
}

/// Relative path from `base` to `path`, using forward slashes
/// (Go `filepath.Rel` + `filepath.ToSlash`).
pub fn rel_slash(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .map(|p| p.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"))
        .unwrap_or_else(|_| path.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn format_byte_size_units() {
        assert_eq!(format_byte_size(8 << 20), "8 MiB");
        assert_eq!(format_byte_size(4 << 10), "4 KiB");
        assert_eq!(format_byte_size(100), "100 bytes");
        assert_eq!(format_byte_size((1 << 20) + 1), "1048577 bytes");
    }

    #[test]
    fn safe_read_n_truncates_on_a_char_boundary() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("f.md");
        // "aé" is 3 bytes; a 2-byte limit splits the "é".
        fs::write(&path, "a\u{e9}b").unwrap();
        let (text, truncated) = safe_read_n(tmp.path(), &path, 2).unwrap();
        assert!(truncated);
        assert_eq!(text, "a");
        let (text, truncated) = safe_read_n(tmp.path(), &path, 4).unwrap();
        assert!(!truncated);
        assert_eq!(text, "a\u{e9}b");
    }

    #[test]
    fn safe_read_refuses_over_the_limit_only_when_whole_file_needed() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("big.md");
        fs::write(&path, vec![b'x'; (MAX_SKILL_FILE_BYTES + 1) as usize]).unwrap();
        assert!(matches!(
            safe_read(tmp.path(), &path),
            Err(ReadError::TooLarge(_))
        ));
        let (text, truncated) = safe_read_n(tmp.path(), &path, MAX_SKILL_FILE_BYTES).unwrap();
        assert!(truncated);
        assert_eq!(text.len() as u64, MAX_SKILL_FILE_BYTES);
    }

    #[cfg(unix)]
    #[test]
    fn safe_read_refuses_symlinks_and_paths_outside_the_skill() {
        use std::os::unix::fs::symlink;
        let outside = TempDir::new().unwrap();
        let secret = outside.path().join("secret.txt");
        fs::write(&secret, "token").unwrap();

        let skill = TempDir::new().unwrap();
        // A symlinked file is not a regular file.
        symlink(&secret, skill.path().join("link.md")).unwrap();
        assert!(matches!(
            safe_read(skill.path(), &skill.path().join("link.md")),
            Err(ReadError::Unsafe(_))
        ));
        // A regular file reached through a symlinked directory resolves
        // outside the skill.
        symlink(outside.path(), skill.path().join("refs")).unwrap();
        assert!(matches!(
            safe_read(skill.path(), &skill.path().join("refs/secret.txt")),
            Err(ReadError::Unsafe(_))
        ));
        assert!(!resolves_within(skill.path(), &skill.path().join("refs/secret.txt")).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn entries_report_their_own_type_and_walks_skip_symlinked_dirs() {
        use std::os::unix::fs::symlink;
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("real")).unwrap();
        fs::write(tmp.path().join("real/a.md"), "a").unwrap();
        // A link back to its parent would loop if the walk followed it.
        symlink(tmp.path(), tmp.path().join("real/loop")).unwrap();

        let entries = read_dir_sorted(&tmp.path().join("real"));
        let link = entries.iter().find(|e| e.name == "loop").unwrap();
        assert!(!link.is_dir && !link.is_regular);

        let mut files = Vec::new();
        walk_files(tmp.path(), &mut files);
        assert_eq!(files.len(), 2, "{files:?}");
    }
}
