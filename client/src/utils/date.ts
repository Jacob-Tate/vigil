/**
 * SQLite datetime('now') returns "YYYY-MM-DD HH:MM:SS" with no timezone suffix.
 * JS parses bare datetime strings as local time, but SQLite stores UTC.
 * This function forces correct UTC interpretation.
 */
export function parseApiDate(dateStr: string): Date {
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(dateStr)) {
    return new Date(dateStr.replace(" ", "T") + "Z");
  }
  return new Date(dateStr);
}
