import { useState, useEffect, useCallback } from "react";
import { NotificationChannel, NotifierTypeDef } from "../types";
import { getNotifications, getNotifierTypes } from "../api/client";

export function useNotifications() {
  const [channels, setChannels] = useState<NotificationChannel[]>([]);
  const [types, setTypes] = useState<NotifierTypeDef[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetch = useCallback(async () => {
    try {
      const [channelData, typeData] = await Promise.all([
        getNotifications(),
        getNotifierTypes(),
      ]);
      setChannels(channelData);
      setTypes(typeData);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load notifications");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetch();
  }, [fetch]);

  return { channels, types, loading, error, refresh: fetch };
}
