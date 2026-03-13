import { useState, useEffect, useCallback } from "react";
import { CveTargetWithStats } from "../types";
import { getCveTargets } from "../api/client";

export function useCveTargets() {
  const [targets, setTargets] = useState<CveTargetWithStats[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetch = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getCveTargets();
      setTargets(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch CVE targets");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetch();
  }, [fetch]);

  return { targets, loading, error, refetch: fetch };
}
