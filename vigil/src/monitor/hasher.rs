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
