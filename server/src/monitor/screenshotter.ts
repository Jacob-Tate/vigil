import puppeteer from "puppeteer-core";
import { writeFileSync, existsSync, statSync } from "fs";
import { join } from "path";
import { SCREENSHOTS_DIR } from "../db/database";

const SCREENSHOT_MAX_AGE_MS = 60 * 60 * 1000; // 1 hour

const BROWSER_CANDIDATES = [
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium-browser",
  "/usr/bin/chromium",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
];

function findBrowser(): string {
  const envPath = process.env.BROWSER_EXECUTABLE_PATH;
  if (envPath && existsSync(envPath)) return envPath;

  for (const candidate of BROWSER_CANDIDATES) {
    if (existsSync(candidate)) return candidate;
  }

  throw new Error(
    "No Chrome or Edge browser found. Install Google Chrome or Microsoft Edge, " +
    "or set the BROWSER_EXECUTABLE_PATH environment variable."
  );
}

export function screenshotPath(serverId: number): string {
  return join(SCREENSHOTS_DIR, `${serverId}.png`);
}

export function isScreenshotStale(serverId: number): boolean {
  const path = screenshotPath(serverId);
  if (!existsSync(path)) return true;
  const stats = statSync(path);
  return Date.now() - stats.mtimeMs > SCREENSHOT_MAX_AGE_MS;
}

// Only http/https are safe to navigate Chromium to; other schemes
// (file://, javascript:, chrome://, data:, etc.) risk local file
// disclosure or renderer exploitation.
function assertSafeUrl(url: string): void {
  const parsed = new URL(url);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`Unsafe URL scheme for screenshot: ${parsed.protocol}`);
  }
}

export async function captureScreenshot(serverId: number, url: string): Promise<void> {
  assertSafeUrl(url);

  const executablePath = findBrowser();

  const browser = await puppeteer.launch({
    executablePath,
    headless: true,
    args: [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--disable-extensions",
      "--disable-background-networking",
      "--disable-sync",
      "--disable-default-apps",
      "--no-first-run",
      "--mute-audio",
      "--disable-gpu",
    ],
  });

  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });
    await page.goto(url, { waitUntil: "networkidle2", timeout: 15000 });
    const buffer = await page.screenshot({ type: "png" });
    writeFileSync(screenshotPath(serverId), Buffer.from(buffer));
  } finally {
    await browser.close();
  }
}
