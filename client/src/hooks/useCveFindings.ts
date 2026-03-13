import { useState, useEffect, useCallback } from "react";
import { PaginatedCveFindings } from "../types";
import { getCveFindings } from "../api/client";

export function useCveFindings(
  targetId: number,
  page = 1,
  limit = 50,
  sortBy = "cvss_score",
  sortDir: "asc" | "desc" = "desc"
) {
  const [data, setData] = useState<PaginatedCveFindings | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetch = useCallback(async () => {
    setLoading(true);
    try {
      const result = await getCveFindings(targetId, page, limit, sortBy, sortDir);
      setData(result);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch CVE findings");
    } finally {
      setLoading(false);
    }
  }, [targetId, page, limit, sortBy, sortDir]);

  useEffect(() => {
    void fetch();
  }, [fetch]);

  return { data, loading, error, refetch: fetch };
}
