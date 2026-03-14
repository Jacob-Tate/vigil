use once_cell::sync::Lazy;
use regex::Regex;
use similar::{ChangeTag, TextDiff};

const MAX_DIFF_LINES: usize = 500;
const CONTEXT_LINES: usize = 5;

/// Block-level HTML tags that should each appear on their own line when prettifying.
static BLOCK_TAG_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)</?(?:div|p|ul|ol|li|table|tr|td|th|thead|tbody|tfoot|caption|colgroup|section|article|header|footer|nav|aside|main|h[1-6]|form|fieldset|legend|blockquote|pre|figure|figcaption|address|details|summary|dialog|template|head|body|html|meta|link|script|style|title)\b[^>]*>"#,
    ).unwrap()
});

/// Very simple HTML prettifier: puts block tags on their own lines and normalises whitespace.
/// Not as sophisticated as js-beautify, but consistent — which is all the diff system needs.
pub fn prettify(html: &str) -> String {
    // Collapse all whitespace first
    static WS: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+").unwrap());
    let flat = WS.replace_all(html.trim(), " ");

    // Insert newlines before and after each block tag match
    let with_newlines = BLOCK_TAG_RE.replace_all(&flat, "\n$0\n");

    // Collapse multiple blank lines and trim each line
    let lines: Vec<&str> = with_newlines
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();

    lines.join("\n")
}

/// Produce a unified diff string compatible with diff2html on the frontend.
/// `old_html` and `new_html` should already be normalised (dynamic patterns stripped).
pub fn compute_diff(old_html: &str, new_html: &str, label: &str) -> String {
    let old_pretty = prettify(old_html);
    let new_pretty = prettify(new_html);

    let diff = TextDiff::from_lines(&old_pretty, &new_pretty);

    // Build unified diff header to match the `diff` npm package format
    let old_label = format!("{} (old)", label);
    let new_label = format!("{} (new)", label);

    let mut output = format!("--- {}\n+++ {}\n", old_label, new_label);

    for group in diff.grouped_ops(CONTEXT_LINES) {
        // Hunk header
        let first = group.first().unwrap();
        let _last = group.last().unwrap();

        let old_start = first.old_range().start + 1;
        let old_len: usize = group.iter().map(|op| op.old_range().len()).sum();
        let new_start = first.new_range().start + 1;
        let new_len: usize = group.iter().map(|op| op.new_range().len()).sum();

        output.push_str(&format!(
            "@@ -{},{} +{},{} @@\n",
            old_start, old_len, new_start, new_len
        ));

        for op in &group {
            for change in diff.iter_changes(op) {
                let prefix = match change.tag() {
                    ChangeTag::Delete => "-",
                    ChangeTag::Insert => "+",
                    ChangeTag::Equal => " ",
                };
                output.push_str(prefix);
                output.push_str(change.value());
                if !change.value().ends_with('\n') {
                    output.push('\n');
                }
            }
        }
    }

    // Truncate very large diffs
    let lines: Vec<&str> = output.lines().collect();
    if lines.len() > MAX_DIFF_LINES {
        let mut truncated = lines[..MAX_DIFF_LINES].join("\n");
        truncated.push_str(&format!(
            "\n\n... diff truncated at {} lines ({} total) ...",
            MAX_DIFF_LINES,
            lines.len()
        ));
        return truncated;
    }

    output
}

/// Returns true if the unified diff contains at least one actual added or removed line
/// (not just file headers and context lines).
pub fn has_meaningful_changes(patch: &str) -> bool {
    patch.lines().any(|line| {
        (line.starts_with('+') || line.starts_with('-'))
            && !line.starts_with("+++")
            && !line.starts_with("---")
    })
}
