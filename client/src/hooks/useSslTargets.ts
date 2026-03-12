import { useState, useEffect, useCallback } from "react";
import { SslTarget } from "../types";
import { getSslTargets } from "../api/client";

const POLL_INTERVAL_MS = 30_000;

export function useSslTargets() {
  const [targets, setTargets] = useState<SslTarget[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchTargets = useCallback(async () => {
    try {
      const data = await getSslTargets();
      setTargets(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load SSL targets");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchTargets();
    const interval = setInterval(() => { void fetchTargets(); }, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [fetchTargets]);

  return { targets, loading, error, refetch: fetchTargets };
}
