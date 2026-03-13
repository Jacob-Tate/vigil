import { useState, useEffect, useRef, useCallback } from "react";
import { VulnrichmentSyncState } from "../types";
import { getVulnrichmentStatus } from "../api/client";

export function useVulnrichmentStatus() {
  const [status, setStatus] = useState<VulnrichmentSyncState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetch = useCallback(async () => {
    try {
      const s = await getVulnrichmentStatus();
      setStatus(s);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch Vulnrichment status");
    }
  }, []);

  useEffect(() => {
    void fetch();
  }, [fetch]);

  // Poll every 2s while syncing, every 60s otherwise
  useEffect(() => {
    if (intervalRef.current) clearInterval(intervalRef.current);
    const interval = status?.is_syncing ? 2000 : 60000;
    intervalRef.current = setInterval(() => void fetch(), interval);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [status?.is_syncing, fetch]);

  return { status, error, refetch: fetch };
}
