import { useState, useEffect, useCallback } from "react";
import { Server } from "../types";
import { getServers } from "../api/client";

const POLL_INTERVAL_MS = 30_000;

export function useServers() {
  const [servers, setServers] = useState<Server[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchServers = useCallback(async () => {
    try {
      const data = await getServers();
      setServers(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load servers");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchServers();
    const interval = setInterval(() => void fetchServers(), POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [fetchServers]);

  return { servers, loading, error, refresh: fetchServers };
}
