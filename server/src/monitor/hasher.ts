import { createHash } from "crypto";

// Patterns that change on every request and should be stripped before hashing
const DYNAMIC_PATTERNS: RegExp[] = [
  // CSRF / nonce tokens
  /<meta[^>]+name=["']csrf[^"']*["'][^>]*>/gi,
  /<meta[^>]+name=["']_token[^"']*["'][^>]*>/gi,
  /csrf[-_]token["'\s]*[:=]["'\s]*[a-zA-Z0-9+/=_-]{20,}/gi,
  // Timestamps / cache-busters in URLs
  /[?&](?:v|ver|version|t|ts|_)=\d+/gi,
  // Inline scripts that are likely tracking/analytics
  /<script[^>]*>\s*(?:window\.__[A-Z]|gtag|dataLayer|_ga|fbq)[^<]*<\/script>/gi,
  // Session IDs in hidden inputs
  /<input[^>]+type=["']hidden["'][^>]+name=["'][^"']*(?:token|nonce|session)[^"']*["'][^>]*>/gi,
  // Google Analytics / Tag Manager snippets
  /UA-\d+-\d+/gi,
  /GTM-[A-Z0-9]+/gi,
  // Moodle / generic random request IDs embedded in inline scripts
  // e.g. 'random69b28bab616f14' or M.util.js_pending('random...')
  /['"]random[a-f0-9]{8,}['"]/gi,
  // Generic random/nonce tokens assigned to JS variables (hex or base64)
  // e.g. var nonce = "a1b2c3d4e5f6...", data-nonce="WULuTz6I...", token = "abc123..."
  /(?:nonce|rand|token|requesttoken)\s*[=:]\s*["'][a-zA-Z0-9+/=_-]{16,}["']/gi,
  // Session/auth/nonce keys in embedded JSON config (Moodle M.cfg, Laravel, Rails, etc.)
  // e.g. "sesskey":"puHtB6pqvc", "nonce":"WULuTz6I2JKifOLOUJhzTA", "_token":"..."
  /"(?:nonce|sesskey|sessionkey|sess_key|_token|csrfToken|csrf_token|authenticity_token|requestToken)"\s*:\s*"[^"]*"/gi,
];

export function normalizeHtml(html: string, extraPatterns: RegExp[] = []): string {
  let normalized = html;

  for (const pattern of [...DYNAMIC_PATTERNS, ...extraPatterns]) {
    normalized = normalized.replace(pattern, "");
  }

  // Normalize whitespace to avoid changes from formatting only
  return normalized.replace(/\s+/g, " ").trim();
}

export function hashContent(html: string, extraPatterns: RegExp[] = []): string {
  return createHash("sha256").update(normalizeHtml(html, extraPatterns), "utf8").digest("hex");
}
