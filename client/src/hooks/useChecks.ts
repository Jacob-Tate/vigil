import { useState, useEffect, useCallback } from "react";
import { CheckStats, PaginatedChecks } from "../types";
import { getChecks, getCheckStats } from "../api/client";

export function useChecks(serverId: number, page = 1, limit = 50) {
  const [result, setResult] = useState<PaginatedChecks | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetch = useCallback(async () => {
    try {
      const data = await getChecks(serverId, page, limit);
      setResult(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load checks");
    } finally {
      setLoading(false);
    }
  }, [serverId, page, limit]);

  useEffect(() => {
    void fetch();
  }, [fetch]);

  return {
    checks: result?.data ?? [],
    pagination: result?.pagination ?? null,
    loading,
    error,
    refresh: fetch,
  };
}

export function useCheckStats(serverId: number) {
  const [stats, setStats] = useState<CheckStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getCheckStats(serverId)
      .then(setStats)
      .catch(() => setStats(null))
      .finally(() => setLoading(false));
  }, [serverId]);

  return { stats, loading };
}
