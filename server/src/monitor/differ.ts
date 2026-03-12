import { createTwoFilesPatch } from "diff";
import { html as beautifyHtml } from "js-beautify";

const MAX_DIFF_LINES = 500;

const BEAUTIFY_OPTIONS = {
  indent_size: 2,
  wrap_line_length: 120,
  extra_liners: [] as string[],
  preserve_newlines: false,
} as const;

function prettify(html: string): string {
  return beautifyHtml(html, BEAUTIFY_OPTIONS);
}

export function computeDiff(oldHtml: string, newHtml: string, label = "page"): string {
  const patch = createTwoFilesPatch(
    `${label} (old)`,
    `${label} (new)`,
    prettify(oldHtml),
    prettify(newHtml),
    undefined,
    undefined,
    { context: 5 }
  );

  // Truncate very large diffs
  const lines = patch.split("\n");
  if (lines.length > MAX_DIFF_LINES) {
    const truncated = lines.slice(0, MAX_DIFF_LINES);
    truncated.push(`\n... diff truncated at ${MAX_DIFF_LINES} lines (${lines.length} total) ...`);
    return truncated.join("\n");
  }

  return patch;
}

/**
 * Returns true if the unified diff has at least one actual added or removed line
 * (not just file headers and context lines).
 */
export function hasMeaningfulChanges(patch: string): boolean {
  return patch.split("\n").some(
    (line) => (line.startsWith("+") || line.startsWith("-")) && !line.startsWith("+++") && !line.startsWith("---")
  );
}
