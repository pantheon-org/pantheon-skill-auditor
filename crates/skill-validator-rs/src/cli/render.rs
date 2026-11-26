//! Report renderers: `text` (human-readable, default), `json` (stable and
//! machine-parseable), `markdown` (a results table), plus GitHub Actions
//! annotation lines (`--emit-annotations`). Renderers never decide the exit
//! code; they only present the [`CliReport`] built by the runners.

use crate::listing::ListingReport;
use crate::triggers::TriggerReport;
use crate::{ContaminationReport, ContentReport, Level, ValidationResult};

use crate::cli::model::{CliReport, MultiCliReport, OutputFormat};

/// Render `report` in the requested `format` and return the string to print to
/// stdout. Pass results are omitted from text and markdown to keep the gate
/// output focused on findings.
pub fn render(report: &CliReport, format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => render_text(report),
        OutputFormat::Json => render_json(report),
        OutputFormat::Markdown => render_markdown(report),
        OutputFormat::Compact => render_compact(report),
    }
}

/// One line for the skill's outcome, with each warning and error beneath
/// it; passing checks, info results, token counts and analysis sections are
/// left out (Go `report.PrintCompact`, upstream v1.8.0, without the colour).
fn render_compact(report: &CliReport) -> String {
    let icon = if report.errors > 0 {
        "✗"
    } else if report.warnings > 0 {
        "⚠"
    } else {
        "✓"
    };
    let outcome = if report.errors == 0 && report.warnings == 0 {
        "passed".to_string()
    } else {
        compact_counts(report.errors, report.warnings)
    };
    let mut out = format!("{icon} {}: {outcome}\n", report.skill_dir);
    for r in &report.results {
        let icon = match r.level {
            Level::Error => "✗",
            Level::Warning => "⚠",
            _ => continue,
        };
        out.push_str(&format!("    {icon} {}\n", r.message));
    }
    out
}

/// "1 error, 2 warnings", leaving out a zero count.
fn compact_counts(errors: usize, warnings: usize) -> String {
    let mut parts = Vec::new();
    if errors > 0 {
        parts.push(format!("{errors} error{}", plural(errors)));
    }
    if warnings > 0 {
        parts.push(format!("{warnings} warning{}", plural(warnings)));
    }
    parts.join(", ")
}

/// The compact skill lines, then the summary as upstream prints it: a blank
/// line, the verdict, the non-zero totals, and a blank line (Go
/// `PrintMultiCompact`).
fn render_multi_compact(multi: &MultiCliReport) -> String {
    let mut out: String = multi.skills.iter().map(render_compact).collect();
    let n = multi.skills.len();
    out.push_str(&format!(
        "\n{n} skill{} validated: {}\n",
        plural(n),
        multi_verdict(multi)
    ));
    if multi.errors > 0 || multi.warnings > 0 {
        out.push_str(&format!(
            "Total: {}\n",
            compact_counts(multi.errors, multi.warnings)
        ));
    }
    out.push('\n');
    out
}

/// Render several skills' reports: each one as [`render`] would, then the
/// totals (Go `PrintMulti` / `PrintMultiMarkdown` / `PrintMultiJSON`).
pub fn render_multi(multi: &MultiCliReport, format: OutputFormat) -> String {
    match format {
        OutputFormat::Compact => render_multi_compact(multi),
        OutputFormat::Json => {
            serde_json::to_string_pretty(multi).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
        }
        OutputFormat::Text => {
            let rule = "━".repeat(60);
            let mut out = String::new();
            for (i, r) in multi.skills.iter().enumerate() {
                if i > 0 {
                    out.push_str(&format!("{rule}\n"));
                }
                out.push_str(&render_text(r));
            }
            out.push_str(&format!("{rule}\n{}", multi_summary(multi, false)));
            out
        }
        OutputFormat::Markdown => {
            let mut out = String::new();
            for (i, r) in multi.skills.iter().enumerate() {
                if i > 0 {
                    out.push_str("\n---\n\n");
                }
                out.push_str(&render_markdown(r));
            }
            out.push_str(&format!("\n---\n\n{}", multi_summary(multi, true)));
            out
        }
    }
}

/// "N skills validated: all passed" (or "x passed, y failed"), then the
/// totals; a skill passes when it has no errors.
fn multi_summary(multi: &MultiCliReport, markdown: bool) -> String {
    let n = multi.skills.len();
    let verdict = multi_verdict(multi);
    let totals = format!(
        "{} error{}, {} warning{}",
        multi.errors,
        plural(multi.errors),
        multi.warnings,
        plural(multi.warnings),
    );
    if markdown {
        format!(
            "**{n} skill{} validated: {verdict}**\n\n**Total: {totals}**\n",
            plural(n)
        )
    } else {
        format!(
            "{n} skill{} validated: {verdict}\nTotal: {totals}\n",
            plural(n)
        )
    }
}

/// "all passed", or "x passed, y failed" (only "y failed" when none passed).
fn multi_verdict(multi: &MultiCliReport) -> String {
    let failed = multi.skills.iter().filter(|s| s.errors > 0).count();
    let passed = multi.skills.len() - failed;
    if failed == 0 {
        "all passed".to_string()
    } else if passed > 0 {
        format!("{passed} passed, {failed} failed")
    } else {
        format!("{failed} failed")
    }
}

/// Annotation lines for every skill in `multi`.
pub fn render_multi_annotations(multi: &MultiCliReport) -> String {
    multi.skills.iter().map(render_annotations).collect()
}

fn render_json(report: &CliReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

fn render_text(report: &CliReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("Skill: {}\n", report.skill_dir));

    let findings: Vec<&ValidationResult> = report
        .results
        .iter()
        .filter(|r| r.level != Level::Pass)
        .collect();

    if findings.is_empty() && report.results.is_empty() {
        // No structure group ran (e.g. `analyze content`).
    } else if findings.is_empty() {
        out.push_str("  No issues found.\n");
    } else {
        for r in findings {
            out.push_str(&format!("  {}\n", text_line(r)));
        }
    }

    if let Some(triggers) = &report.triggers {
        out.push_str(&render_triggers_text(triggers));
    }
    if let Some(listing) = &report.listing {
        out.push_str(&render_listing_text(listing));
    }
    if let Some(content) = &report.content {
        out.push_str(&render_content_text("Content metrics", content));
    }
    if let Some(contamination) = &report.contamination {
        out.push_str(&render_contamination_text(contamination));
    }
    for rr in &report.reference_reports {
        if let Some(content) = &rr.content {
            out.push_str(&render_content_text(
                &format!("Content ({})", rr.file),
                content,
            ));
        }
    }

    if !report.results.is_empty() {
        out.push_str(&format!(
            "Summary: {} error{}, {} warning{}\n",
            report.errors,
            plural(report.errors),
            report.warnings,
            plural(report.warnings),
        ));
    }
    out
}

fn text_line(r: &ValidationResult) -> String {
    let level = r.level.as_str().to_uppercase();
    let location = location(&r.file, r.line);
    if location.is_empty() {
        format!("[{level}] {}: {}", r.category, r.message)
    } else {
        format!("[{level}] {}: {} ({location})", r.category, r.message)
    }
}

fn render_triggers_text(t: &TriggerReport) -> String {
    if t.new_skill {
        return "Trigger phrases: new skill, nothing to compare.\n".to_string();
    }
    if t.dropped.is_empty() {
        return format!(
            "Trigger phrases: all {} base phrase(s) preserved.\n",
            t.base_phrases.len()
        );
    }
    let mut out = format!(
        "Trigger phrases (advisory): {} of {} base phrase(s) dropped:\n",
        t.dropped.len(),
        t.base_phrases.len()
    );
    for p in &t.dropped {
        out.push_str(&format!("  - {p}\n"));
    }
    out.push_str(
        "  Confirm the description still names each intent (a deliberate consolidation), \
         or restore the phrase.\n",
    );
    out
}

fn render_triggers_markdown(t: &TriggerReport) -> String {
    if t.new_skill {
        return "New skill, no trigger phrases to compare.\n\n".to_string();
    }
    if t.dropped.is_empty() {
        return format!(
            "All {} base trigger phrase(s) preserved.\n\n",
            t.base_phrases.len()
        );
    }
    let mut out = format!(
        "{} of {} base trigger phrase(s) dropped (advisory):\n\n",
        t.dropped.len(),
        t.base_phrases.len()
    );
    for p in &t.dropped {
        out.push_str(&format!("- `{}`\n", p.replace('`', "'")));
    }
    out.push('\n');
    out
}

/// Largest contributors shown in the text and markdown listing reports.
const LISTING_TOP: usize = 10;

fn render_listing_text(l: &ListingReport) -> String {
    let mut out = format!(
        "Listing budget (estimate, advisory):\n  {} skills, {} chars of {} budget ({}); \
         {} excluded by disable-model-invocation\n  budget: {}\n",
        l.entries.len(),
        l.total_chars,
        l.budget_chars,
        if l.over_budget() { "OVER" } else { "within" },
        l.excluded_disabled,
        l.budget_source,
    );
    for b in &l.bands {
        out.push_str(&format!(
            "  band: {} tokens -> {} chars ({})\n",
            b.context_tokens,
            b.budget_chars,
            if b.over { "OVER" } else { "within" },
        ));
    }
    for n in &l.notes {
        out.push_str(&format!("  note: {n}\n"));
    }
    for (domain, chars) in &l.by_domain {
        out.push_str(&format!("  domain {domain}: {chars}\n"));
    }
    out.push_str("  largest:\n");
    for e in l.entries.iter().take(LISTING_TOP) {
        let cut = if e.truncated { " (truncated)" } else { "" };
        out.push_str(&format!("    {:>5}  {}{cut}\n", e.chars, e.path));
    }
    for u in &l.unreadable {
        out.push_str(&format!("  unreadable, not counted: {u}\n"));
    }
    out
}

fn render_listing_markdown(l: &ListingReport) -> String {
    let mut out = format!(
        "{} skills, **{}** of {} chars ({}); {} excluded by `disable-model-invocation`. \
         Estimate only; the live budget depends on the model and settings.\n\n",
        l.entries.len(),
        l.total_chars,
        l.budget_chars,
        if l.over_budget() {
            "over budget"
        } else {
            "within budget"
        },
        l.excluded_disabled,
    );
    out.push_str(&format!("Budget: {}.\n\n", l.budget_source));
    if !l.bands.is_empty() {
        out.push_str(
            "| Context window | Budget | Verdict |\n| -------------- | ------ | ------- |\n",
        );
        for b in &l.bands {
            out.push_str(&format!(
                "| {} tokens | {} | {} |\n",
                b.context_tokens,
                b.budget_chars,
                if b.over { "over" } else { "within" },
            ));
        }
        out.push('\n');
    }
    out.push_str("| Domain | Chars |\n| ------ | ----- |\n");
    for (domain, chars) in &l.by_domain {
        out.push_str(&format!("| {} | {chars} |\n", escape_pipes(domain)));
    }
    out.push_str("\n| Largest skills | Chars |\n| -------------- | ----- |\n");
    for e in l.entries.iter().take(LISTING_TOP) {
        out.push_str(&format!("| {} | {} |\n", escape_pipes(&e.path), e.chars));
    }
    out.push('\n');
    out
}

fn render_content_text(title: &str, c: &ContentReport) -> String {
    format!(
        "{title}:\n  words={} code_blocks={} sentences={} imperative={} \
         sections={} list_items={}\n  code_block_ratio={:.4} imperative_ratio={:.4} \
         information_density={:.4} instruction_specificity={:.4}\n  code_languages={:?}\n",
        c.word_count,
        c.code_block_count,
        c.sentence_count,
        c.imperative_count,
        c.section_count,
        c.list_item_count,
        c.code_block_ratio,
        c.imperative_ratio,
        c.information_density,
        c.instruction_specificity,
        c.code_languages,
    )
}

fn render_contamination_text(c: &ContaminationReport) -> String {
    format!(
        "Contamination:\n  level={} score={:.4} scope_breadth={} language_mismatch={}\n  \
         primary_category={} mismatched_categories={:?}\n",
        c.contamination_level,
        c.contamination_score,
        c.scope_breadth,
        c.language_mismatch,
        c.primary_category,
        c.mismatched_categories,
    )
}

fn render_markdown(report: &CliReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("# Validation report: `{}`\n\n", report.skill_dir));

    if let Some(triggers) = &report.triggers {
        out.push_str(&render_triggers_markdown(triggers));
    }
    if let Some(listing) = &report.listing {
        out.push_str(&render_listing_markdown(listing));
    }

    let findings: Vec<&ValidationResult> = report
        .results
        .iter()
        .filter(|r| r.level != Level::Pass)
        .collect();

    if !report.results.is_empty() {
        if findings.is_empty() {
            out.push_str("No issues found.\n\n");
        } else {
            out.push_str("| Level | Category | Message | Location |\n");
            out.push_str("| ----- | -------- | ------- | -------- |\n");
            for r in findings {
                out.push_str(&format!(
                    "| {} | {} | {} | {} |\n",
                    r.level.as_str(),
                    escape_pipes(&r.category),
                    escape_pipes(&r.message),
                    escape_pipes(&location(&r.file, r.line)),
                ));
            }
            out.push('\n');
        }
        out.push_str(&format!(
            "**{} error{}, {} warning{}**\n",
            report.errors,
            plural(report.errors),
            report.warnings,
            plural(report.warnings),
        ));
    }

    if let Some(content) = &report.content {
        out.push_str(&markdown_content(content));
    }
    out
}

fn markdown_content(c: &ContentReport) -> String {
    format!(
        "\n## Content metrics\n\n\
         - Words: {}\n- Code blocks: {}\n- Sentences: {}\n- Imperative sentences: {}\n\
         - Sections: {}\n- List items: {}\n- Code-block ratio: {:.4}\n\
         - Imperative ratio: {:.4}\n- Information density: {:.4}\n\
         - Instruction specificity: {:.4}\n",
        c.word_count,
        c.code_block_count,
        c.sentence_count,
        c.imperative_count,
        c.section_count,
        c.list_item_count,
        c.code_block_ratio,
        c.imperative_ratio,
        c.information_density,
        c.instruction_specificity,
    )
}

/// GitHub Actions annotation lines for every error and warning finding
/// (`::error` / `::warning`). Pass/Info results are not annotated.
pub fn render_annotations(report: &CliReport) -> String {
    let mut out = String::new();
    for r in &report.results {
        let command = match r.level {
            Level::Error => "error",
            Level::Warning => "warning",
            _ => continue,
        };
        let props = annotation_props(&report.skill_dir, &r.file, r.line);
        let message = escape_annotation_data(&format!("{}: {}", r.category, r.message));
        out.push_str(&format!("::{command}{props}::{message}\n"));
    }
    out
}

/// The `file=...,line=...` property block, joining the skill directory to the
/// result's relative file. Empty when the result carries no file.
fn annotation_props(skill_dir: &str, file: &str, line: usize) -> String {
    if file.is_empty() {
        return String::new();
    }
    let path = escape_annotation_prop(&format!("{skill_dir}/{file}"));
    if line > 0 {
        format!(" file={path},line={line}")
    } else {
        format!(" file={path}")
    }
}

fn location(file: &str, line: usize) -> String {
    match (file.is_empty(), line) {
        (true, _) => String::new(),
        (false, 0) => file.to_string(),
        (false, n) => format!("{file}:{n}"),
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

fn escape_pipes(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

/// Escape a workflow-command data segment (GitHub Actions message escaping).
fn escape_annotation_data(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

/// Escape a workflow-command property value (additionally escapes `,` and `:`).
fn escape_annotation_prop(s: &str) -> String {
    escape_annotation_data(s)
        .replace(',', "%2C")
        .replace(':', "%3A")
}
