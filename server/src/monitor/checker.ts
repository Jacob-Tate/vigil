import axios from "axios";
import { CheckResult } from "../types";

const REQUEST_TIMEOUT_MS = 15_000;

export async function checkServer(
  url: string,
  responseTimeThresholdMs: number
): Promise<CheckResult> {
  const start = Date.now();

  try {
    const response = await axios.get<string>(url, {
      timeout: REQUEST_TIMEOUT_MS,
      validateStatus: () => true, // never throw on HTTP error status
      responseType: "text",
      headers: {
        "User-Agent": "Monitor/1.0 (uptime checker)",
      },
      maxRedirects: 5,
    });

    const responseTimeMs = Date.now() - start;
    const statusCode = response.status;
    const rawHtml = typeof response.data === "string" ? response.data : String(response.data);

    const isSuccessStatus = statusCode >= 200 && statusCode < 400;
    const isWithinThreshold = responseTimeMs <= responseTimeThresholdMs;
    const isUp = isSuccessStatus && isWithinThreshold;

    return { statusCode, responseTimeMs, isUp, rawHtml };
  } catch (err) {
    const responseTimeMs = Date.now() - start;
    const error = err as Error;
    const message = axios.isAxiosError(err)
      ? (err.code ?? err.message)
      : error.message;

    return {
      statusCode: null,
      responseTimeMs,
      isUp: false,
      rawHtml: "",
      error: message,
    };
  }
}
