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
];

export function hashContent(html: string): string {
  let normalized = html;

  for (const pattern of DYNAMIC_PATTERNS) {
    normalized = normalized.replace(pattern, "");
  }

  // Normalize whitespace to avoid hash changes from formatting only
  normalized = normalized.replace(/\s+/g, " ").trim();

  return createHash("sha256").update(normalized, "utf8").digest("hex");
}
