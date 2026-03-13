/**
 * Validates critical environment variables at startup.
 *
 * In production (NODE_ENV=production): logs an error and exits for each
 * dangerous misconfiguration so the server never silently serves broken
 * or insecure behaviour.
 *
 * In development: logs a warning so developers know what to set before
 * deploying.
 */
export function validateEnv(): void {
  const isProd = process.env.NODE_ENV === "production";
  const issues: string[] = [];

  // JWT_SECRET must be set and not the example placeholder
  const jwtSecret = process.env.JWT_SECRET ?? "";
  if (!jwtSecret) {
    issues.push("JWT_SECRET is not set — sessions cannot be signed");
  } else if (jwtSecret === "change-me-to-a-long-random-string") {
    issues.push("JWT_SECRET is still the example placeholder — replace it with a long random secret");
  }

  // ADMIN_PASSWORD must not be the example placeholder
  const adminPassword = process.env.ADMIN_PASSWORD ?? "";
  if (adminPassword === "change-me") {
    issues.push("ADMIN_PASSWORD is still the example placeholder — set a strong password");
  }

  // BASE_URL must not be localhost in production — alert links would be unreachable
  const baseUrl = process.env.BASE_URL ?? "http://localhost:5173";
  if (isProd && baseUrl.includes("localhost")) {
    issues.push(
      `BASE_URL is "${baseUrl}" — alert notification links will point to localhost and be unreachable outside this machine`
    );
  }

  // CLIENT_ORIGIN must not be localhost in production — CORS will reject real browsers
  const clientOrigin = process.env.CLIENT_ORIGIN ?? "http://localhost:5173";
  if (isProd && clientOrigin.includes("localhost")) {
    issues.push(
      `CLIENT_ORIGIN is "${clientOrigin}" — CORS will block requests from your actual frontend origin`
    );
  }

  if (issues.length === 0) return;

  if (isProd) {
    for (const issue of issues) {
      console.error(`[config] FATAL: ${issue}`);
    }
    process.exit(1);
  } else {
    for (const issue of issues) {
      console.warn(`[config] WARNING: ${issue}`);
    }
  }
}
