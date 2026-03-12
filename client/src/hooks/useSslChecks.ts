import { useState, useEffect, useCallback } from "react";
import { SslCheck, SslCheckStats, PaginatedSslChecks } from "../types";
import { getSslChecks, getSslCheckStats } from "../api/client";

export function useSslChecks(targetId: number, page = 1, limit = 50) {
  const [data, setData] = useState<PaginatedSslChecks | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchChecks = useCallback(async () => {
    try {
      const result = await getSslChecks(targetId, page, limit);
      setData(result);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load SSL checks");
    } finally {
      setLoading(false);
    }
  }, [targetId, page, limit]);

  useEffect(() => {
    void fetchChecks();
  }, [fetchChecks]);

  return {
    checks: data?.data ?? [] as SslCheck[],
    pagination: data?.pagination ?? null,
    loading,
    error,
    refetch: fetchChecks,
  };
}

export function useSslCheckStats(targetId: number) {
  const [stats, setStats] = useState<SslCheckStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getSslCheckStats(targetId)
      .then(setStats)
      .catch(() => { /* stats are supplemental */ })
      .finally(() => setLoading(false));
  }, [targetId]);

  return { stats, loading };
}
