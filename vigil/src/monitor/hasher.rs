use once_cell::sync::Lazy;
use regex::Regex;
use sha2::{Digest, Sha256};

/// Patterns that change on every request and should be stripped before hashing.
/// Mirrors the 12-pattern DYNAMIC_PATTERNS array in hasher.ts.
static DYNAMIC_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    let patterns = [
        // CSRF / nonce tokens in meta tags
        r#"(?i)<meta[^>]+name=["']csrf[^"']*["'][^>]*>"#,
        r#"(?i)<meta[^>]+name=["']_token[^"']*["'][^>]*>"#,
        // CSRF token values
        r#"(?i)csrf[-_]token["'\s]*[:=]["'\s]*[a-zA-Z0-9+/=_-]{20,}"#,
        // Timestamps / cache-busters in URLs
        r#"(?i)[?&](?:v|ver|version|t|ts|_)=\d+"#,
        // Inline scripts that are likely tracking/analytics
        r#"(?i)<script[^>]*>\s*(?:window\.__[A-Z]|gtag|dataLayer|_ga|fbq)[^<]*</script>"#,
        // Session IDs in hidden inputs
        r#"(?i)<input[^>]+type=["']hidden["'][^>]+name=["'][^"']*(?:token|nonce|session)[^"']*["'][^>]*>"#,
        // Google Analytics tracking IDs
        r#"(?i)UA-\d+-\d+"#,
        // Google Tag Manager IDs
        r#"(?i)GTM-[A-Z0-9]+"#,
        // Moodle / generic random request IDs
        r#"(?i)['"]random[a-f0-9]{8,}['"]]"#,
        // Generic random/nonce tokens assigned to JS variables
        r#"(?i)(?:nonce|rand|token|requesttoken)\s*[=:]\s*["'][a-zA-Z0-9+/=_-]{16,}["']"#,
        // Session/auth/nonce keys in embedded JSON config
        r#"(?i)"(?:nonce|sesskey|sessionkey|sess_key|_token|csrfToken|csrf_token|authenticity_token|requestToken)"\s*:\s*"[^"]*""#,
    ];

    patterns
        .iter()
        .filter_map(|p| match Regex::new(p) {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::warn!("Failed to compile DYNAMIC_PATTERN `{}`: {}", p, e);
                None
            }
        })
        .collect()
});

/// Strip dynamic content patterns and collapse whitespace.
pub fn normalize_html(html: &str, extra_patterns: &[Regex]) -> String {
    let mut s = html.to_string();

    for pattern in DYNAMIC_PATTERNS.iter().chain(extra_patterns.iter()) {
        s = pattern.replace_all(&s, "").into_owned();
    }

    // Collapse all whitespace to a single space
    static WHITESPACE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+").unwrap());
    WHITESPACE.replace_all(s.trim(), " ").into_owned()
}

/// SHA-256 hex of the normalized HTML content.
pub fn hash_content(html: &str, extra_patterns: &[Regex]) -> String {
    let normalized = normalize_html(html, extra_patterns);
    let digest = Sha256::digest(normalized.as_bytes());
    format!("{:x}", digest)
}

/// Parse a JSON array of regex strings (from server.ignore_patterns) into compiled Regexes.
pub fn parse_ignore_patterns(patterns_json: Option<&str>) -> Vec<Regex> {
    let Some(json) = patterns_json else {
        return Vec::new();
    };

    let Ok(parsed) = serde_json::from_str::<Vec<serde_json::Value>>(json) else {
        return Vec::new();
    };

    parsed
        .into_iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .filter(|s| !s.is_empty())
        .filter_map(|s| match Regex::new(&format!("(?i){}", s)) {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::warn!("Ignoring invalid user pattern `{}`: {}", s, e);
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- normalize_html ---

    #[test]
    fn collapses_whitespace() {
        let html = "  hello   world  \n\t  foo  ";
        assert_eq!(normalize_html(html, &[]), "hello world foo");
    }

    #[test]
    fn strips_csrf_meta_tag() {
        let html = r#"<html><meta name="csrf-token" content="abc123def456ghi789jkl0"><p>ok</p></html>"#;
        let result = normalize_html(html, &[]);
        assert!(!result.contains("csrf-token"));
        assert!(result.contains("ok"));
    }

    #[test]
    fn strips_csrf_token_value() {
        let html = r#"<input name="csrf_token: abcdefghijklmnopqrstuvwxyz123">"#;
        let result = normalize_html(html, &[]);
        assert!(!result.contains("abcdefghijklmnopqrstuvwxyz123"));
    }

    #[test]
    fn strips_google_analytics_id() {
        let html = r#"<script>ga('create', 'UA-12345-6', 'auto');</script>"#;
        let result = normalize_html(html, &[]);
        assert!(!result.contains("UA-12345-6"));
    }

    #[test]
    fn strips_gtm_id() {
        let html = r#"<p>GTM-ABCDEF</p>"#;
        let result = normalize_html(html, &[]);
        assert!(!result.contains("GTM-ABCDEF"));
    }

    #[test]
    fn custom_ignore_pattern_applied() {
        let pattern = Regex::new(r"(?i)\$[\d.]+").unwrap();
        let html = "<p>Price: $99.99 — Buy now!</p>";
        let result = normalize_html(html, &[pattern]);
        assert!(!result.contains("99.99"));
        assert!(result.contains("Buy now!"));
    }

    #[test]
    fn content_without_dynamic_parts_unchanged_except_whitespace() {
        let html = "  <p>Static content</p>  ";
        let result = normalize_html(html, &[]);
        assert_eq!(result, "<p>Static content</p>");
    }

    // --- hash_content ---

    #[test]
    fn hash_is_deterministic() {
        let html = "<html><body>Hello, world!</body></html>";
        assert_eq!(hash_content(html, &[]), hash_content(html, &[]));
    }

    #[test]
    fn different_content_yields_different_hash() {
        let a = hash_content("<p>Version A</p>", &[]);
        let b = hash_content("<p>Version B</p>", &[]);
        assert_ne!(a, b);
    }

    #[test]
    fn whitespace_only_diff_yields_same_hash() {
        // Extra spaces vs newlines between identical content should normalize to the same hash
        let a = hash_content("<p>Hello</p>   <p>World</p>", &[]);
        let b = hash_content("<p>Hello</p>\n<p>World</p>", &[]);
        assert_eq!(a, b);
    }

    #[test]
    fn hash_is_64_char_hex_string() {
        let hash = hash_content("anything", &[]);
        assert_eq!(hash.len(), 64, "SHA-256 digest should be 64 hex chars");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // --- parse_ignore_patterns ---

    #[test]
    fn none_returns_empty() {
        assert!(parse_ignore_patterns(None).is_empty());
    }

    #[test]
    fn valid_json_array_compiles_patterns() {
        let json = r#"["hello", "world\\d+"]"#;
        let patterns = parse_ignore_patterns(Some(json));
        assert_eq!(patterns.len(), 2);
    }

    #[test]
    fn invalid_json_returns_empty() {
        assert!(parse_ignore_patterns(Some("not json")).is_empty());
    }

    #[test]
    fn invalid_regex_entries_skipped() {
        // "[unclosed" is not a valid regex (unclosed character class)
        let json = r#"["valid_pattern", "[unclosed"]"#;
        let patterns = parse_ignore_patterns(Some(json));
        assert_eq!(patterns.len(), 1, "invalid regex should be silently skipped");
    }

    #[test]
    fn empty_strings_skipped() {
        let json = r#"["", "valid", ""]"#;
        let patterns = parse_ignore_patterns(Some(json));
        assert_eq!(patterns.len(), 1);
    }
}
