use std::path::PathBuf;

/// Chrome/Edge executable candidates to try when no env var is set.
const BROWSER_CANDIDATES: &[&str] = &[
    // Windows — Chrome
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    // Windows — Edge
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    // macOS — Chrome
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    // macOS — Edge
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    // Linux — Chrome / Chromium
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
];

/// Find the browser executable: checks `BROWSER_EXECUTABLE_PATH` env var first,
/// then each candidate path.
pub fn find_browser() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("BROWSER_EXECUTABLE_PATH") {
        let p = PathBuf::from(&path);
        if p.exists() {
            return Ok(p);
        }
        return Err(format!(
            "BROWSER_EXECUTABLE_PATH is set to '{}' but the file does not exist",
            path
        ));
    }

    for &candidate in BROWSER_CANDIDATES {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return Ok(p);
        }
    }

    Err("No Chrome/Edge browser found. Install Chrome or set BROWSER_EXECUTABLE_PATH.".into())
}

/// Returns the path where a server's screenshot PNG is stored.
pub fn screenshot_path(data_dir: &str, server_id: i64) -> PathBuf {
    PathBuf::from(data_dir)
        .join("screenshots")
        .join(format!("{}.png", server_id))
}

/// Reject non-http/https URLs to prevent arbitrary command injection.
fn assert_safe_url(url: &str) -> Result<(), String> {
    let lower = url.to_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        Ok(())
    } else {
        Err(format!("Unsafe URL rejected for screenshot: {}", url))
    }
}

/// Capture a screenshot of `url` and save it to `{data_dir}/screenshots/{server_id}.png`.
/// Errors are logged but do not propagate — callers should fire-and-forget via `tokio::spawn`.
pub async fn capture_screenshot(data_dir: &str, server_id: i64, url: &str) {
    if let Err(e) = assert_safe_url(url) {
        tracing::warn!("[screenshot] {}", e);
        return;
    }

    let browser = match find_browser() {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("[screenshot] {}", e);
            return;
        }
    };

    let dest = screenshot_path(data_dir, server_id);
    // Convert to an absolute path so the browser flag works regardless of CWD.
    let dest_abs = match dest.canonicalize().or_else(|_| {
        std::env::current_dir().map(|cwd| cwd.join(&dest))
    }) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("[screenshot] Could not resolve output path for server {}: {}", server_id, e);
            return;
        }
    };

    let screenshot_arg = format!("--screenshot={}", dest_abs.display());

    let status = tokio::process::Command::new(&browser)
        .args([
            "--headless",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-extensions",
            "--disable-background-networking",
            "--mute-audio",
            "--window-size=1280,800",
            &screenshot_arg,
            url,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;

    match status {
        Err(e) => {
            tracing::error!("[screenshot] Failed to launch browser for server {}: {}", server_id, e);
        }
        Ok(s) if !s.success() => {
            tracing::warn!(
                "[screenshot] Browser exited with non-zero status for server {}: {:?}",
                server_id,
                s.code()
            );
        }
        Ok(_) => {
            tracing::debug!("[screenshot] Saved screenshot for server {}", server_id);
        }
    }
}
