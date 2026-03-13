import { useState, useEffect, useRef, useCallback } from "react";
import { NvdSyncStatus } from "../types";
import { getNvdStatus } from "../api/client";

export function useNvdStatus() {
  const [status, setStatus] = useState<NvdSyncStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetch = useCallback(async () => {
    try {
      const s = await getNvdStatus();
      setStatus(s);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch status");
    }
  }, []);

  useEffect(() => {
    void fetch();
  }, [fetch]);

  // Poll every 2s while importing, every 30s otherwise
  useEffect(() => {
    if (intervalRef.current) clearInterval(intervalRef.current);
    const interval = status?.isImporting ? 2000 : 30000;
    intervalRef.current = setInterval(() => void fetch(), interval);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [status?.isImporting, fetch]);

  return { status, error, refetch: fetch };
}
