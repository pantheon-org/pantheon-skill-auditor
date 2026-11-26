//! Content quality analysis (Go `content` package). Computes word/code/sentence
//! metrics and directive-marker ratios. All floats are rounded to 4dp, matching
//! the Go tool. Regexes use `(?-u:...)` where Go relies on ASCII `\w`/`\b`, and
//! `\s` is spelled out as `[ \t\n\x0C\r]` to match Go's RE2 `\s` exactly
//! (Rust's ASCII `\s` would also include the vertical tab `\x0B`).

use std::sync::LazyLock;

use regex::Regex;

use crate::types::ContentReport;
use crate::util::{self, round_to};

/// Strong directive-language markers (Go `content.strongMarkerRes`).
const STRONG_MARKERS: &[&str] = &[
    r"must",
    r"always",
    r"never",
    r"shall",
    r"required",
    r"do not",
    r"don't",
    r"ensure",
    r"critical",
    r"mandatory",
];

/// Weak/advisory-language markers (Go `content.weakMarkerRes`).
const WEAK_MARKERS: &[&str] = &[
    r"may",
    r"consider",
    r"could",
    r"might",
    r"optional",
    r"possibly",
    r"suggested",
    r"prefer",
    r"try to",
    r"if possible",
];

fn compile_markers(words: &[&str]) -> Vec<Regex> {
    words
        .iter()
        .map(|w| Regex::new(&format!(r"(?-u:\b{w}\b)")).expect("marker regex"))
        .collect()
}

static STRONG_RES: LazyLock<Vec<Regex>> = LazyLock::new(|| compile_markers(STRONG_MARKERS));
static WEAK_RES: LazyLock<Vec<Regex>> = LazyLock::new(|| compile_markers(WEAK_MARKERS));

/// English imperative verbs, matched as a sentence's first word (Go
/// `imperative_default.yaml`, `languages.en.verbs`).
const IMPERATIVE_VERBS: &[&str] = &[
    "use",
    "run",
    "create",
    "add",
    "set",
    "install",
    "configure",
    "write",
    "read",
    "check",
    "verify",
    "make",
    "build",
    "test",
    "ensure",
    "include",
    "remove",
    "delete",
    "update",
    "call",
    "import",
    "export",
    "define",
    "implement",
    "return",
    "pass",
    "handle",
    "parse",
    "generate",
    "format",
    "validate",
    "convert",
    "follow",
    "apply",
    "start",
    "stop",
    "avoid",
    "keep",
    "do",
    "execute",
    "open",
    "close",
    "save",
    "load",
    "send",
    "receive",
];

/// Chinese imperative verbs, matched as a sentence prefix (Go
/// `imperative_default.yaml`, `languages.zh.verbs`, upstream v1.8.0).
const ZH_IMPERATIVE_VERBS: &[&str] = &[
    "使用",
    "运行",
    "创建",
    "添加",
    "设置",
    "安装",
    "配置",
    "编写",
    "读取",
    "检查",
    "验证",
    "构建",
    "测试",
    "确保",
    "删除",
    "更新",
    "调用",
    "导入",
    "导出",
    "定义",
    "实现",
    "处理",
    "解析",
    "生成",
    "格式化",
    "转换",
    "执行",
    "打开",
    "关闭",
    "保存",
    "加载",
    "发送",
    "接收",
];

/// Chinese imperative keywords, matched anywhere in a sentence (Go
/// `languages.zh.keywords`): Chinese imperatives do not always start with a
/// verb.
const ZH_IMPERATIVE_KEYWORDS: &[&str] = &[
    "请", "务必", "确保", "必须", "一定", "切勿", "不要", "禁止", "务须", "需要",
];

/// Any Han character (Go `unicode.Is(unicode.Han, r)`).
static HAN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\p{Han}").expect("HAN"));

/// Chinese sentence boundaries (Go `chineseSentencePat`).
static ZH_SENTENCE_SPLIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[。！？；\n]+").expect("ZH_SENTENCE_SPLIT"));

static CODE_LANG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u:(?:```|~~~)(\w+))").expect("CODE_LANG"));

static SENTENCE_SPLIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[.!?][ \t\n\x0C\r]+|[.!?]$|\n\n+").expect("SENTENCE_SPLIT"));

static LEADING_FORMAT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[#*>\-\t\n\x0C\r ]+").expect("LEADING_FORMAT"));

static SECTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^#{2,}[ \t\n\x0C\r]+").expect("SECTION"));

static LIST_ITEM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t\n\x0C\r]*[-*+][ \t\n\x0C\r]+|^[ \t\n\x0C\r]*[0-9]+\.[ \t\n\x0C\r]+")
        .expect("LIST_ITEM")
});

/// Compute content metrics for SKILL.md content (Go `content.Analyze`).
pub fn analyze(content: &str) -> ContentReport {
    if content.trim().is_empty() {
        return ContentReport::default();
    }

    let word_count = content.split_whitespace().count();

    // Code block analysis.
    let mut code_block_count = 0usize;
    let mut code_block_words = 0usize;
    for cap in util::CODE_BLOCK_PATTERN.captures_iter(content) {
        code_block_count += 1;
        if let Some(body) = cap.get(1) {
            code_block_words += body.as_str().split_whitespace().count();
        }
    }
    let code_block_ratio = if word_count > 0 {
        code_block_words as f64 / word_count as f64
    } else {
        0.0
    };

    // Code languages (document order).
    let code_languages: Vec<String> = CODE_LANG
        .captures_iter(content)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .collect();

    // Sentence analysis.
    let sentences = count_sentences(content);
    let sentence_count = sentences.len();
    let imperative_count = count_imperative_sentences(&sentences);
    let imperative_ratio = if sentence_count > 0 {
        imperative_count as f64 / sentence_count as f64
    } else {
        0.0
    };

    // Information density.
    let information_density = if code_block_count > 0 {
        code_block_ratio * 0.5 + imperative_ratio * 0.5
    } else {
        imperative_ratio
    };

    // Marker analysis.
    let strong_count = count_marker_matches(content, &STRONG_RES);
    let weak_count = count_marker_matches(content, &WEAK_RES);
    let total_markers = strong_count + weak_count;
    let instruction_specificity = if total_markers > 0 {
        strong_count as f64 / total_markers as f64
    } else {
        0.0
    };

    let section_count = SECTION.find_iter(content).count();
    let list_item_count = LIST_ITEM.find_iter(content).count();

    ContentReport {
        word_count,
        code_block_count,
        code_block_ratio: round_to(code_block_ratio, 4),
        code_languages,
        sentence_count,
        imperative_count,
        imperative_ratio: round_to(imperative_ratio, 4),
        information_density: round_to(information_density, 4),
        strong_markers: strong_count,
        weak_markers: weak_count,
        instruction_specificity: round_to(instruction_specificity, 4),
        section_count,
        list_item_count,
    }
}

fn has_chinese(s: &str) -> bool {
    HAN.is_match(s)
}

/// Split text into sentences, with code removed (Go
/// `imperativeDetector.splitSentences`). Text with no Han character takes the
/// English splitter alone, exactly as before upstream v1.8.0; text with one
/// is split on Chinese punctuation first.
fn count_sentences(text: &str) -> Vec<String> {
    let stripped = util::CODE_BLOCK_STRIP.replace_all(text, "");
    let stripped = util::INLINE_CODE_STRIP.replace_all(&stripped, "");
    if has_chinese(&stripped) {
        split_mixed(&stripped)
    } else {
        split_english(&stripped)
    }
}

/// Keep a trimmed part when it is longer than 5 bytes. Go: `len(s) > 5` is a
/// BYTE-length check, so two Han characters (6 bytes) pass.
fn push_sentence(out: &mut Vec<String>, part: &str) {
    let s = part.trim();
    if s.len() > 5 {
        out.push(s.to_string());
    }
}

/// Split on English sentence boundaries (Go `splitEnglish`).
fn split_english(text: &str) -> Vec<String> {
    let mut sentences = Vec::new();
    for part in SENTENCE_SPLIT.split(text) {
        push_sentence(&mut sentences, part);
    }
    sentences
}

/// Split text holding Chinese (Go `splitMixed`): on Chinese punctuation first,
/// then a segment with no Han character goes through the English splitter,
/// and one with Han characters is split on English boundaries only when it
/// has `.`, `!` or `?`.
fn split_mixed(text: &str) -> Vec<String> {
    let mut sentences = Vec::new();
    for part in ZH_SENTENCE_SPLIT.split(text) {
        let s = part.trim();
        if s.is_empty() {
            continue;
        }
        if !has_chinese(s) {
            sentences.extend(split_english(s));
        } else if s.contains(['.', '!', '?']) {
            for sub in SENTENCE_SPLIT.split(s) {
                push_sentence(&mut sentences, sub);
            }
        } else {
            push_sentence(&mut sentences, s);
        }
    }
    sentences
}

/// Whether a sentence is imperative (Go `imperativeDetector.isImperative`).
/// A sentence with Han characters is imperative when it starts with a Chinese
/// verb or holds a Chinese keyword; any sentence is imperative when its first
/// word is an English verb.
fn is_imperative(sentence: &str) -> bool {
    let cleaned = LEADING_FORMAT.replace(sentence, "");
    if has_chinese(&cleaned)
        && (ZH_IMPERATIVE_VERBS.iter().any(|v| cleaned.starts_with(v))
            || ZH_IMPERATIVE_KEYWORDS.iter().any(|k| cleaned.contains(k)))
    {
        return true;
    }
    cleaned
        .split_whitespace()
        .next()
        .is_some_and(|first| IMPERATIVE_VERBS.contains(&first.to_lowercase().as_str()))
}

fn count_imperative_sentences(sentences: &[String]) -> usize {
    sentences.iter().filter(|s| is_imperative(s)).count()
}

fn count_marker_matches(text: &str, patterns: &[Regex]) -> usize {
    let lower = text.to_lowercase();
    patterns.iter().map(|re| re.find_iter(&lower).count()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ported from upstream v1.8.0 `content/content_test.go`.

    #[test]
    fn chinese_verbs_start_imperative_sentences() {
        let r = analyze("使用CLI工具。运行测试。这是一个描述。创建一个新文件。");
        assert_eq!(r.sentence_count, 4);
        assert_eq!(r.imperative_count, 3);
    }

    #[test]
    fn chinese_keywords_mark_imperatives_anywhere() {
        assert_eq!(
            analyze("请确保所有测试通过。务必按照规范操作。").imperative_count,
            2
        );
        assert!(is_imperative("请确保所有测试通过"));
        assert!(!is_imperative("这只是一个普通句子"));
    }

    #[test]
    fn chinese_punctuation_splits_sentences() {
        assert_eq!(
            analyze("使用此工具。运行测试！确保正确？配置环境；这是说明。").sentence_count,
            5
        );
    }

    #[test]
    fn mixed_chinese_and_english() {
        let r = analyze("Use the CLI tool. 运行测试。Create a new file. 请确保代码质量。");
        assert_eq!(r.sentence_count, 4);
        assert_eq!(r.imperative_count, 4);
        assert_eq!(
            count_sentences("Use the tool.运行测试。Create a file.").len(),
            2
        );
    }

    #[test]
    fn non_imperative_chinese() {
        assert_eq!(
            analyze("这是一个描述。项目已完成。功能正常工作。").imperative_count,
            0
        );
        assert!(!is_imperative("项目已经完成了"));
    }

    #[test]
    fn has_chinese_detects_han() {
        assert!(!has_chinese("Hello world"));
        assert!(has_chinese("使用此工具"));
        assert!(has_chinese("Use 使用 both"));
        assert!(!has_chinese("12345"));
        assert!(!has_chinese(""));
    }

    #[test]
    fn english_detection_is_unchanged() {
        assert!(is_imperative("Use the CLI tool"));
        assert!(!is_imperative("This is a description"));
        assert!(is_imperative("## Use the tool"));
        assert!(is_imperative("- Run the tests"));
        assert!(!is_imperative("**Create** a file"));
        assert!(is_imperative("  Set the value"));
    }

    #[test]
    fn chinese_full_content() {
        let md =
            "# 我的技能\n\n## 使用说明\n\n使用CLI工具验证技能。你必须始终在发布前运行测试。\n\n\
                  ```bash\nskill-validator validate ./my-skill\n```\n\n## 配置\n\n\
                  创建配置文件。设置输出格式。你可以考虑使用JSON。\n\n\
                  - 步骤 1：安装\n- 步骤 2：配置\n- 步骤 3：运行\n\n请确保所有检查通过。\n";
        let r = analyze(md);
        assert_eq!(r.code_block_count, 1);
        assert_eq!(r.section_count, 2);
        assert!(r.imperative_count >= 3, "{r:?}");
    }

    #[test]
    fn empty_content_is_default() {
        assert_eq!(analyze("   \n  "), ContentReport::default());
    }

    #[test]
    fn code_languages_preserve_document_order() {
        let md = "```python\nx\n```\ntext\n```bash\ny\n```";
        let r = analyze(md);
        assert_eq!(r.code_languages, vec!["python", "bash"]);
        assert_eq!(r.code_block_count, 2);
    }

    #[test]
    fn markers_and_specificity() {
        let md = "You must always do this. You may consider that.";
        let r = analyze(md);
        // strong: must, always -> 2 (plain "do" is not a strong marker; only
        // "do not" is) ; weak: may, consider -> 2
        assert_eq!(r.strong_markers, 2);
        assert_eq!(r.weak_markers, 2);
        assert_eq!(r.instruction_specificity, round_to(2.0 / 4.0, 4));
    }

    #[test]
    fn ascii_word_boundary_ignores_substrings() {
        // "must" inside "mustache" must NOT match (ASCII \b).
        let r = analyze("The mustache is optional here now.");
        assert_eq!(r.strong_markers, 0);
        assert_eq!(r.weak_markers, 1); // "optional"
    }
}
