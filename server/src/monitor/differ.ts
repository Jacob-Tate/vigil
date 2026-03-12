import { createTwoFilesPatch } from "diff";

const MAX_DIFF_LINES = 500;

export function computeDiff(oldHtml: string, newHtml: string, label = "page"): string {
  const patch = createTwoFilesPatch(
    `${label} (old)`,
    `${label} (new)`,
    oldHtml,
    newHtml,
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
